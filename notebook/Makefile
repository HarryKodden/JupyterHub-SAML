# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

.DEFAULT_GOAL=build

include ../.env

notebook_image: Dockerfile
	docker build -t $(MY_LOCAL_NOTEBOOK_IMAGE) \
		--build-arg JUPYTERHUB_VERSION=$(MY_JUPYTERHUB_VERSION) \
		--build-arg DOCKER_NOTEBOOK_IMAGE=$(MY_DOCKER_NOTEBOOK_IMAGE) \
		.

build: notebook_image
