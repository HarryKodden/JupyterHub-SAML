# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

.DEFAULT_GOAL=build

JUPYTERHUB_VERSION=0.8.0
DOCKER_NOTEBOOK_IMAGE=jupyter/scipy-notebook
LOCAL_NOTEBOOK_IMAGE=jupyterhub-user

notebook_image: Dockerfile
	docker build -t $(LOCAL_NOTEBOOK_IMAGE) \
		--build-arg JUPYTERHUB_VERSION=$(JUPYTERHUB_VERSION) \
		--build-arg DOCKER_NOTEBOOK_IMAGE=$(DOCKER_NOTEBOOK_IMAGE) \
		.

build: notebook_image
