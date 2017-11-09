#ARG DOCKER_NOTEBOOK_IMAGE
ARG DOCKER_NOTEBOOK_IMAGE
FROM $DOCKER_NOTEBOOK_IMAGE

ARG JUPYTERHUB_VERSION
RUN python3 -m pip install --no-cache jupyterhub==$JUPYTERHUB_VERSION

USER root

# R pre-requisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    fonts-dejavu \
    gfortran \
    gcc && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Julia dependencies
# install Julia packages in /opt/julia instead of $HOME
ENV JULIA_PKGDIR=/opt/julia

RUN . /etc/os-release && \
    echo "deb http://ppa.launchpad.net/staticfloat/juliareleases/ubuntu $VERSION_CODENAME main" > /etc/apt/sources.list.d/julia.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3D3D3ACC && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    julia && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    echo "push!(Libdl.DL_LOAD_PATH, \"$CONDA_DIR/lib\")" >> /usr/etc/julia/juliarc.jl && \
    mkdir $JULIA_PKGDIR && \
    chown $NB_USER $JULIA_PKGDIR && \
    fix-permissions $JULIA_PKGDIR

USER $NB_USER

# R packages including IRKernel which gets installed globally.
RUN conda config --system --add channels r
RUN conda install --quiet --yes \
    'rpy2=2.8*'
RUN conda install --quiet --yes \
    'r-base=3.3.2'
RUN conda install --quiet --yes \
    'r-irkernel=0.7*'
RUN conda install --quiet --yes \
    'r-plyr=1.8*'
RUN conda install --quiet --yes \
    'r-devtools=1.12*'
RUN conda install --quiet --yes \
    'r-tidyverse=1.0*'
RUN conda install --quiet --yes \
    'r-shiny=0.14*'
RUN conda install --quiet --yes \
    'r-rmarkdown=1.2*'
RUN conda install --quiet --yes \
    'r-forecast=7.3*'
RUN conda install --quiet --yes \
    'r-rsqlite=1.1*'
RUN conda install --quiet --yes \
    'r-reshape2=1.4*'
RUN conda install --quiet --yes \
    'r-nycflights13=0.2*'
RUN conda install --quiet --yes \
    'r-caret=6.0*'
RUN conda install --quiet --yes \
    'r-rcurl=1.95*'
RUN conda install --quiet --yes \
    'r-crayon=1.3*'
RUN conda install --quiet --yes \
    'r-randomforest=4.6*'
RUN    conda clean -tipsy && \
    fix-permissions $CONDA_DIR

# Add Julia packages
# Install IJulia as jovyan and then move the kernelspec out
# to the system share location. Avoids problems with runtime UID change not
# taking effect properly on the .local folder in the jovyan home dir.
RUN julia -e 'Pkg.init()'
RUN julia -e 'Pkg.update()'
RUN julia -e 'Pkg.add("HDF5")'
RUN julia -e 'Pkg.add("Gadfly")'
RUN julia -e 'Pkg.add("RDatasets")'
RUN julia -e 'Pkg.add("IJulia")'
# Precompile Julia packages
RUN CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt && julia -e 'using HDF5'
RUN julia -e 'using Gadfly'
RUN julia -e 'using RDatasets'
RUN julia -e 'using IJulia'
# move kernelspec out of home
RUN mv $HOME/.local/share/jupyter/kernels/julia* $CONDA_DIR/share/jupyter/kernels/ && \
    chmod -R go+rx $CONDA_DIR/share/jupyter && \
    rm -rf $HOME/.local && \
    fix-permissions $JULIA_PKGDIR $CONDA_DIR/share/jupyter

