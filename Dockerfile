from centos:7
#from vergissberlin/centos-development

RUN yum -y groupinstall "Development Tools" \
    && yum -y install wget \
    && wget http://software.intel.com/sites/landingpage/pintool/downloads/pin-3.6-97554-g31f0a167d-gcc-linux.tar.gz -P /tmp \
    && tar xzvf  /tmp/pin-3.6-97554-g31f0a167d-gcc-linux.tar.gz -C /opt \
    && rm -f /tmp/pin-3.6-97554-g31f0a167d-gcc-linux.tar.gz \
    && rm -rf /var/cache/yum

ENV PIN_ROOT=/opt/pin-3.6-97554-g31f0a167d-gcc-linux
CMD /bin/bash



