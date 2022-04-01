# FROM bitnami/rabbitmq:3.8.9-debian-10-r64
# FROM bitnami/rabbitmq:3.9.5-debian-10-r6
FROM bitnami/rabbitmq:3.8.22-debian-10-r11

# FROM default-route-openshift-image-registry.apps.tinaaocp01.nfvdev.tlabs.ca/naaf-develop-zerotouch/rabbitmq:3.8.9-debian-10-r64

USER root

# RUN chgrp -R 0 /opt/bitnami && chmod -R g=u /opt/bitnami

# RUN touch /opt/bitnami/rabbitmq/etc/rabbitmq/advanced.config
# RUN touch /opt/bitnami/rabbitmq/etc/rabbitmq/rabbitmq.conf
# RUN touch /opt/bitnami/rabbitmq/.rabbitmq/.erlang.cookie

# COPY ./advamced.config /opt/bitnami/rabbitmq/etc/rabbitmq/advanced.config
# COPY ./rabbitmq.conf /opt/bitnami/rabbitmq/etc/rabbitmq/rabbitmq.conf

# COPY . /opt/bitnami/rabbitmq/etc/rabbitmq/
# RUN chmod +rwx /opt/bitnami/rabbitmq/etc/rabbitmq/advanced.config
# RUN chmod +rwx /opt/bitnami/rabbitmq/etc/rabbitmq/rabbitmq.conf

# RUN chmod -R +rwx /opt/bitnami

# RUN chmod -R u=rwx,g=rwx,o=rx /opt/bitnami
# RUN chmod -R g+w /opt/bitnami/rabbitmq/etc/rabbitmq/
# RUN chmod -R g+w /opt/bitnami/rabbitmq/.rabbitmq/
# RUN chown -R 1001:1001 /opt/bitnami

# RUN chown -R 1000760000:1000760000 /opt/bitnami
RUN chown -R 1000760000 /opt/bitnami

# RUN chown -R root:root /opt/bitnami
# check owner ship of default images
# check group of default images

# USER 1001

USER 1000760000

RUN rabbitmq-plugins enable rabbitmq_auth_backend_oauth2

RUN rabbitmq-plugins enable rabbitmq_management

RUN rabbitmq-plugins enable rabbitmq_management_agent

# RUN rabbitmq-plugins enable rabbitmq_auth_backend_internal

RUN rabbitmq-plugins enable rabbitmq_web_dispatch

# command to enable HA
# RUN rabbitmqctl set_policy ha-all "" '{"ha-mode":"all","ha-sync-mode":"automatic"}'

# command to enable specific vhost for ha
# rabbitmqctl set_policy -p "REPLACE_WITH_VHOST_NAME" ha-all "" '{"ha-mode":"all","ha-sync-mode":"automatic"}'