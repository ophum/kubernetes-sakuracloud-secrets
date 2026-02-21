/*
Copyright 2026 ophum.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ogen-go/ogen/validate"
	secretsv1beta1 "github.com/ophum/kubernetes-sakuracloud-secrets/api/v1beta1"
	"github.com/sacloud/saclient-go"
	"go.yaml.in/yaml/v3"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"

	sm "github.com/sacloud/secretmanager-api-go"
	smv1 "github.com/sacloud/secretmanager-api-go/apis/v1"
)

// SakuraCloudSecretReconciler reconciles a SakuraCloudSecret object
type SakuraCloudSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SakuraCloudSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/reconcile
func (r *SakuraCloudSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var s secretsv1beta1.SakuraCloudSecret
	if err := r.Get(ctx, req.NamespacedName, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Info("failed to get secret")
		return ctrl.Result{}, err
	}

	log.Info("reconcile secret",
		"name", req.NamespacedName.String(),
		"specVersion", s.Spec.Version,
		"currentVersion", s.Status.Version,
	)

	var ksecret corev1.Secret
	isNotFound := false
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: s.Namespace,
		Name:      s.Spec.DestinationSecretName,
	}, &ksecret); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		isNotFound = true
	} else {
		if s.Spec.Version != nil && *s.Spec.Version == s.Status.Version {
			return ctrl.Result{}, nil
		}
	}

	var apiKey corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: s.Namespace,
		Name:      s.Spec.APIKey.SecretName,
	}, &apiKey); err != nil {
		return ctrl.Result{}, err
	}

	accessToken, ok := apiKey.Data["accessToken"]
	if !ok {
		log.Info("data", "data", apiKey.Data)
		return ctrl.Result{}, errors.New("accessToken required")
	}
	accessTokenSecret, ok := apiKey.Data["accessTokenSecret"]
	if !ok {
		return ctrl.Result{}, errors.New("accessToken required")
	}

	log.Info("apiKey", "accessToken", string(accessToken))
	apiClient := &saclient.Client{}
	apiClient.SetWith(saclient.WithBasicAuth(string(accessToken), string(accessTokenSecret)))
	client, err := sm.NewClient(apiClient)
	if err != nil {
		return ctrl.Result{}, err
	}

	var version smv1.OptNilInt
	if s.Spec.Version != nil {
		version = smv1.NewOptNilInt(*s.Spec.Version)
	}
	unveiled, err := client.SecretmanagerVaultsSecretsUnveil(ctx, &smv1.WrappedUnveil{
		Secret: smv1.Unveil{
			Name:    s.Spec.Name,
			Version: version,
		},
	}, smv1.SecretmanagerVaultsSecretsUnveilParams{
		VaultResourceID: strconv.FormatInt(int64(s.Spec.VaultResourceID), 10),
	})
	if err != nil {
		// NOTE: 明らかにリソースIDや認証情報が間違っている場合はConditionをFalseにして終了する
		var resErr *validate.UnexpectedStatusCodeError
		if errors.As(err, &resErr) {
			switch resErr.StatusCode {
			case 401, 403, 404, 500:
				meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
					Type:    "SyncSecret",
					Status:  metav1.ConditionFalse,
					Reason:  "created",
					Message: resErr.Error(),
				})

				if err := r.Status().Update(ctx, &s); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
		}

		return ctrl.Result{
			RequeueAfter: time.Minute,
		}, err
	}

	var secretData map[string]string
	switch s.Spec.Format {
	case "", "json":
		if err := json.Unmarshal([]byte(unveiled.Secret.Value), &secretData); err != nil {
			return ctrl.Result{
				RequeueAfter: time.Minute,
			}, err
		}
	case "yaml":
		if err := yaml.Unmarshal([]byte(unveiled.Secret.Value), &secretData); err != nil {
			return ctrl.Result{
				RequeueAfter: time.Minute,
			}, err
		}
	default:
		return ctrl.Result{}, errors.New("invalid format")
	}

	data := map[string][]byte{}
	for k, v := range secretData {
		data[k] = []byte(v)
	}

	if isNotFound {
		ksecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.Spec.DestinationSecretName,
				Namespace: s.Namespace,
			},
			Data: data,
		}
		if err := ctrl.SetControllerReference(&s, &ksecret, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, &ksecret); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		ksecret.Data = data
		if err := ctrl.SetControllerReference(&s, &ksecret, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Update(ctx, &ksecret); err != nil {
			return ctrl.Result{}, err
		}
	}

	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:    "SyncSecret",
		Status:  metav1.ConditionTrue,
		Reason:  "synced",
		Message: "secret synced",
	})
	s.Status.Version = unveiled.Secret.Version.Value

	if err := r.Status().Update(ctx, &s); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SakuraCloudSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Secret{}, ".metadata.controller", func(o client.Object) []string {
		secret := o.(*corev1.Secret)
		owner := metav1.GetControllerOf(secret)
		if owner == nil {
			return nil
		}

		if owner.APIVersion != secretsv1beta1.GroupVersion.String() || owner.Kind != "Secret" {
			return nil
		}

		return []string{owner.Name}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SakuraCloudSecret{}).
		Owns(&corev1.Secret{}).
		Named("sakuracloudsecret").
		Complete(r)
}
