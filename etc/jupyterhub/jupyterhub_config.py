import os

# Google OAuth

# GitHub OAuth
OAUTH_CLIENT_ID="15fdebb8190771b58fe9"
OAUTH_CLIENT_SECRET="493f62484d0f939c80426bc2a71dfae327f0fdc7"
OAUTH_CALLBACK_URL="https://www.myvelocity.nl/jupyter/hub/oauth_callback"

# Name of Docker machine
DOCKER_MACHINE_NAME="jupyter"

# Docker notebook image
#DOCKER_NOTEBOOK_IMAGE="jupyterhub-user"
DOCKER_NOTEBOOK_IMAGE="jupyterhub-user"

# Notebook directory for the single-user server
DOCKER_NOTEBOOK_DIR="/volumes/jupyter/notebooks"

# Docker run command to use when spawning single-user containers
DOCKER_SPAWN_CMD="/srv/singleuser/singleuser.sh"

# Notebook to run in for the single-user server
NOTEBOOK="user.ipynb"

# Hosted Domain
HOSTED_DOMAIN="jupyter"

# DNS Name or address IP
HUB_IP_CONNECT="jupyter"

# Name of JupyterHub container data volume
DATA_VOLUME_HOST="jupyterhub-data"

# Data volume container mount point
DATA_VOLUME_CONTAINER="/data"

c.JupyterHub.config_file = '/srv/jupyterhub/jupyterhub_config.py'
c.JupyterHub.hub_ip = 'jupyter'
c.JupyterHub.hub_port = 8080
c.JupyterHub.base_url = '/'
#c.JupyterHub.port = 443

#c.JupyterHub.ssl_cert = os.environ['SSL_CERT']
#c.JupyterHub.ssl_key = os.environ['SSL_KEY']
c.JupyterHub.confirm_no_ssl = True

c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'
# JupyterHub requires a single-user instance of the Notebook server, so we
# default to using the `start-singleuser.sh` script included in the
# jupyter/docker-stacks *-notebook images as the Docker run command when
# spawning containers.  Optionally, you can override the Docker run command
#network_name = os.environ.get('DOCKER_NETWORK_NAME')
network_name = 'jupyterhubsaml_back-end'
c.DockerSpawner.use_internal_ip = True
c.DockerSpawner.network_name = network_name

import dockerspawner
c.DockerSpawner.format_volume_name = dockerspawner.volumenamingstrategy.escaped_format_volume_name
# Pass the network name as argument to spawned containers
c.DockerSpawner.extra_host_config = { 'network_mode': network_name }
#c.DockerSpawner.extra_start_kwargs = { 'network_mode': network_name }
# Explicitly set notebook directory because we'll be mounting a host volume to
# it.  Most jupyter/docker-stacks *-notebook images run the Notebook server as
# user `jovyan`, and set the notebook directory to `/home/jovyan/work`.
# We follow the same convention.
notebook_dir = '/home/jovyan/work'
c.DockerSpawner.notebook_dir = notebook_dir
# Mount the real user's Docker volume on the host to the notebook user's
# notebook directory in the container
c.DockerSpawner.volumes = { 'jupyterhub-user-{username}': notebook_dir }
c.DockerSpawner.extra_create_kwargs.update({ 'volume_driver': 'local' })
# Remove containers once they are stopped
c.DockerSpawner.remove_containers = True
# For debugging arguments passed to spawned containers
c.DockerSpawner.debug = True

c.DockerSpawner.image = DOCKER_NOTEBOOK_IMAGE

spawn_cmd = os.environ.get('DOCKER_SPAWN_CMD', "start-singleuser.sh")
c.DockerSpawner.extra_create_kwargs.update({ 'command': spawn_cmd })

#c.DockerSpawner.network_name = network_name
#c.DockerSpawner.extra_start_kwargs = { 'network_mode': network_name }
#c.DockerSpawner.hub_ip_connect = 'jupyterhub'
#c.DockerSpawner.host_ip = "0.0.0.0"

#c.JupyterHub.authenticator_class = 'oauthenticator.GitHubOAuthenticator'
#c.GitHubOAuthenticator.client_id = OAUTH_CLIENT_ID
#c.GitHubOAuthenticator.client_secret = OAUTH_CLIENT_SECRET
#c.GitHubOAuthenticator.oauth_callback_url = OAUTH_CALLBACK_URL
####c.GitHubOAuthenticator.hosted_domain = os.environ['HOSTED_DOMAIN']
c.JupyterHub.authenticator_class = 'jhub_remote_user_authenticator.remote_user_auth.RemoteUserAuthenticator'

#c.Spawner.tls_assert_hostname = False
c.DockerSpawner.tls_verify = False

c.Authenticator.admin_users = whitelist = set()
c.Authenticator.whitelist = admin = set()

#join = os.path.join
#here = os.path.dirname(__file__)
#with open(join(here, 'userList')) as f:
#    for line in f:
#        if not line:
#            continue
#        parts = line.split()
#        name = parts[0]
#        whitelist.add(name)
#        if len(parts) > 1 and parts[1] == 'admin':
##            admin.add(name)
