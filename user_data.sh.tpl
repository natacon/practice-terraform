#!/usr/bin/env bash
yum install -y ${package}
systemctl start ${package}.service
