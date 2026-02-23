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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"text/template"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/ogen-go/ogen/validate"
	"github.com/ophum/kubernetes-sakuracloud-secrets/api/v1beta1"
	secretsv1beta1 "github.com/ophum/kubernetes-sakuracloud-secrets/api/v1beta1"
	"github.com/sacloud/saclient-go"
	"go.yaml.in/yaml/v3"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"

	sm "github.com/sacloud/secretmanager-api-go"
	smv1 "github.com/sacloud/secretmanager-api-go/apis/v1"
)

const (
	typeSyncSecret = "SyncSecret"
)

// SakuraCloudSecretReconciler reconciles a SakuraCloudSecret object
type SakuraCloudSecretReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.t-inagaki.net,resources=sakuracloudsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

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
		"vaultResourceID", s.Spec.VaultResourceID,
		"specVersion", s.Spec.Version,
		"currentVersion", s.Status.Version,
		"deletionTimestamp", s.DeletionTimestamp,
	)

	if !s.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// FIXME: Validating ladmission webhookでやるのがよさそう
	if err := r.validateFormat(s.Spec.Format); err != nil {
		return ctrl.Result{}, err
	}

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

	client, err := r.newSecretManagerClient(ctx, s.Namespace, s.Spec.APIKey.SecretName)
	if err != nil {
		return ctrl.Result{}, nil
	}

	var version smv1.OptNilInt
	if s.Spec.Version != nil {
		version = smv1.NewOptNilInt(*s.Spec.Version)
	}

	log.Info("unveil secret",
		"version", s.Spec.Version,
	)
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
			r.Recorder.Eventf(&s, nil, corev1.EventTypeWarning, "UnveilFailed", "Unveil", "Failed to unveil secret from SakuraCloud: %d/%s, error=%s", s.Spec.VaultResourceID, s.Spec.Name, err.Error())
			switch resErr.StatusCode {
			case 401, 403, 404, 500:
				meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
					Type:    typeSyncSecret,
					Status:  metav1.ConditionFalse,
					Reason:  "synced",
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
	data := map[string][]byte{}
	var unmarshaler func([]byte, any) error
	switch s.Spec.Format {
	case "", "json":
		unmarshaler = json.Unmarshal
	case "yaml":
		unmarshaler = yaml.Unmarshal
	}

	if len(s.Spec.TemplateData) == 0 {
		var secretData map[string]string
		if err := unmarshaler([]byte(unveiled.Secret.Value), &secretData); err != nil {
			r.Recorder.Eventf(&s, nil, corev1.EventTypeWarning, "UnmarshalFailed", "Unmarshal", "Failed to unmarshal data: %d/%s, error=%s", s.Spec.VaultResourceID, s.Spec.Name, err.Error())
			meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
				Type:    typeSyncSecret,
				Status:  metav1.ConditionFalse,
				Reason:  "synced",
				Message: err.Error(),
			})
			if err := r.Status().Update(ctx, &s); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		for k, v := range secretData {
			data[k] = []byte(v)
		}
	} else {
		var secretData map[string]any
		if err := unmarshaler([]byte(unveiled.Secret.Value), &secretData); err != nil {
			r.Recorder.Eventf(&s, nil, corev1.EventTypeWarning, "UnmarshalFailed", "Unmarshal", "Failed to unmarshal data: %d/%s, error=%s", s.Spec.VaultResourceID, s.Spec.Name, err.Error())
			meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
				Type:    typeSyncSecret,
				Status:  metav1.ConditionFalse,
				Reason:  "synced",
				Message: err.Error(),
			})
			if err := r.Status().Update(ctx, &s); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		data, err = r.renderTemplateData(ctx, &s, secretData)
		if err != nil {
			r.Recorder.Eventf(&s, nil, corev1.EventTypeWarning, "RenderTemplateFailed", "RenderTemplate", "Failed to parse template: %d/%s, error=%s", s.Spec.VaultResourceID, s.Spec.Name, err.Error())
			meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
				Type:    typeSyncSecret,
				Status:  metav1.ConditionFalse,
				Reason:  "synced",
				Message: err.Error(),
			})
			if err := r.Status().Update(ctx, &s); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
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
		Type:    typeSyncSecret,
		Status:  metav1.ConditionTrue,
		Reason:  "synced",
		Message: "secret synced",
	})
	s.Status.Version = unveiled.Secret.Version.Value

	if err := r.Status().Update(ctx, &s); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(&s, nil, corev1.EventTypeNormal, "Synced", "Sync", "Successfully synced secret from SakuraCloud: %d/%s", s.Spec.VaultResourceID, s.Spec.Name)

	return ctrl.Result{}, nil
}

func (r *SakuraCloudSecretReconciler) newSecretManagerClient(ctx context.Context, namespace, name string) (*smv1.Client, error) {
	log := logf.FromContext(ctx)
	var apiKey corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}, &apiKey); err != nil {
		return nil, err
	}

	accessToken, ok := apiKey.Data["accessToken"]
	if !ok {
		return nil, errors.New("accessToken required")
	}
	accessTokenSecret, ok := apiKey.Data["accessTokenSecret"]
	if !ok {
		return nil, errors.New("accessToken required")
	}

	log.Info("sakuracloud credentials loaded", "accessToken", string(accessToken))
	apiClient := &saclient.Client{}
	apiClient.SetWith(saclient.WithBasicAuth(string(accessToken), string(accessTokenSecret)))
	return sm.NewClient(apiClient)

}

func (r *SakuraCloudSecretReconciler) validateFormat(format string) error {
	switch format {
	case "", "json", "yaml":
		return nil
	default:
		return errors.New("invalid format")
	}
}

func (r *SakuraCloudSecretReconciler) renderTemplateData(ctx context.Context, s *v1beta1.SakuraCloudSecret, secretData map[string]any) (map[string][]byte, error) {
	data := map[string][]byte{}
	for k, v := range s.Spec.TemplateData {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		templ, err := template.New("").Parse(v)
		if err != nil {
			return nil, err
		}
		b := bytes.Buffer{}
		if err := templ.Execute(&b, secretData); err != nil {
			return nil, err
		}
		data[k] = b.Bytes()
	}
	return data, nil
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
