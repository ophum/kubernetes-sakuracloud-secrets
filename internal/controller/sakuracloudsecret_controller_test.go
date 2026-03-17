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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1beta1 "github.com/ophum/kubernetes-sakuracloud-secrets/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

func TestDetectSecretType(t *testing.T) {
	tests := []struct {
		name string
		data map[string][]byte
		want corev1.SecretType
	}{
		{
			name: "dockerconfigjson",
			data: map[string][]byte{
				corev1.DockerConfigJsonKey: []byte(`{"auths":{"example.com":{"auth":"xxx"}}}`),
			},
			want: corev1.SecretTypeDockerConfigJson,
		},
		{
			name: "dockercfg",
			data: map[string][]byte{
				corev1.DockerConfigKey: []byte(`{"example.com":{"auth":"xxx"}}`),
			},
			want: corev1.SecretTypeDockercfg,
		},
		{
			name: "tls",
			data: map[string][]byte{
				corev1.TLSCertKey:       []byte("cert"),
				corev1.TLSPrivateKeyKey: []byte("key"),
			},
			want: corev1.SecretTypeTLS,
		},
		{
			name: "opaque",
			data: map[string][]byte{
				"foo": []byte("bar"),
			},
			want: corev1.SecretTypeOpaque,
		},
		{
			name: "tls-cert-only",
			data: map[string][]byte{
				corev1.TLSCertKey: []byte("cert"),
			},
			want: corev1.SecretTypeOpaque,
		},
		{
			name: "tls-key-only",
			data: map[string][]byte{
				corev1.TLSPrivateKeyKey: []byte("key"),
			},
			want: corev1.SecretTypeOpaque,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSecretType(tt.data)
			if got != tt.want {
				t.Errorf("got=%s want=%s", got, tt.want)
			}
		})
	}
}

func TestSelectSecretType(t *testing.T) {
	tests := []struct {
		name     string
		specType corev1.SecretType
		data     map[string][]byte
		want     corev1.SecretType
	}{
		{
			name:     "spec type takes precedence - Opaque",
			specType: corev1.SecretTypeOpaque,
			data: map[string][]byte{
				corev1.DockerConfigJsonKey: []byte(`{"auths":{"example.com":{"auth":"xxx"}}}`),
			},
			want: corev1.SecretTypeOpaque,
		},
		{
			name:     "spec type takes precedence - TLS",
			specType: corev1.SecretTypeTLS,
			data: map[string][]byte{
				"foo": []byte("bar"),
			},
			want: corev1.SecretTypeTLS,
		},
		{
			name:     "spec type takes precedence - DockerConfigJson",
			specType: corev1.SecretTypeDockerConfigJson,
			data: map[string][]byte{
				"foo": []byte("bar"),
			},
			want: corev1.SecretTypeDockerConfigJson,
		},
		{
			name:     "empty spec type uses auto-detect - dockerconfigjson",
			specType: "",
			data: map[string][]byte{
				corev1.DockerConfigJsonKey: []byte(`{"auths":{"example.com":{"auth":"xxx"}}}`),
			},
			want: corev1.SecretTypeDockerConfigJson,
		},
		{
			name:     "empty spec type uses auto-detect - tls",
			specType: "",
			data: map[string][]byte{
				corev1.TLSCertKey:       []byte("cert"),
				corev1.TLSPrivateKeyKey: []byte("key"),
			},
			want: corev1.SecretTypeTLS,
		},
		{
			name:     "empty spec type uses auto-detect - opaque",
			specType: "",
			data: map[string][]byte{
				"foo": []byte("bar"),
			},
			want: corev1.SecretTypeOpaque,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectSecretType(tt.specType, tt.data)
			if got != tt.want {
				t.Errorf("got=%s want=%s", got, tt.want)
			}
		})
	}
}

var _ = Describe("SakuraCloudSecret Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		sakuracloudsecret := &secretsv1beta1.SakuraCloudSecret{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SakuraCloudSecret")
			err := k8sClient.Get(ctx, typeNamespacedName, sakuracloudsecret)
			if err != nil && errors.IsNotFound(err) {
				resource := &secretsv1beta1.SakuraCloudSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &secretsv1beta1.SakuraCloudSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance SakuraCloudSecret")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &SakuraCloudSecretReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
