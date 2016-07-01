#!/bin/bash
# DCHQ On-Premise Installer - http://dchq.co
# 2016-03-18

DCHQ_LOG_PATH=/var/log/dchq
mkdir -p ${DCHQ_LOG_PATH}

NGINX_SSL=/opt/dchq/nginx/ssl/
mkdir -p ${NGINX_SSL}

POSTGRES_DATA=/opt/dchq/postgres/data
mkdir -p ${POSTGRES_DATA}

LOGFILE="${DCHQ_LOG_PATH}/`hostname`.dchq.io_agent_run.`date +%m%d%Y.%H%M%S`"
CPU_COUNT="$(cat /proc/cpuinfo | grep "siblings" | sort -u | cut -d: -f2)"
MEM="$(grep MemTotal /proc/meminfo|awk '{printf ("%s\t%s\n", $2/1024,$3)}'| sed 's/k/M/')"
OS="$(awk '/DISTRIB_ID=/' /etc/*-release | sed 's/DISTRIB_ID=//' | tr '[:upper:]' '[:lower:]')"
VERSION="$(awk '/DISTRIB_RELEASE=/' /etc/*-release | sed 's/DISTRIB_RELEASE=//' | sed 's/[.]0/./')"
SHELL_VAR_COUNT=$#
TMP=/tmp

DOCKER_CRED_FILE=/root/.dockercfg
DCHQ_USER=dchq


DCHQ_TAG=latest
NGINX_SSL_PORT="443"
DCHQ_POSTGRES_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
DCHQ_RABBITMQ_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
DCHQ_SMTP_HOST="localhost"
DCHQ_SMTP_PORT="25"
DCHQ_SMTP_USERNAME=""
DCHQ_SMTP_PASSWORD=""
DCHQ_SMTP_AUTH=true
DCHQ_SMTP_SOCKET_PORT=465
DCHQ_EMAIL_FROM=""
DCHQ_EMAIL_BCC=""
DCHQ_EMAIL_FAILURE_TO=""
HTTP_PROXY_ENABLED=false
PROXY_AUTH=false
DEB_DOCKER_CONFIG=/etc/default/docker
RPM_DOCKER_CONFIG=/etc/sysconfig/docker
DCHQ_CONTAINERS="dchq-redis dchq-solr dchq-rabbitmq dchq-postgres dchq-tomcat"


############################################
#  Defining Functions....
############################################


OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`

GetVersionFromFile()
{
        VERSION=`cat $1 | tr "\n" ' ' | sed s/.*VERSION.*=\ // `
}

function check_distro() {
        KERNEL=`uname -r`
        if [ -f /etc/centos-release ] ; then
                DIST='CentOS'
		elif [ -f /etc/oracle-release ] ; then
				DIST='Oracle'
                PSUEDONAME=`cat /etc/oracle-release | sed s/.*\(// | sed s/\)//`
                REV=`cat /etc/oracle-release | sed s/.*release\ // | sed s/\ .*//`
		elif [ -f /etc/redhat-release ] && [ ! -f /etc/oracle-release ]; then
                DIST='RedHat'
                PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
                REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/SUSE-release ] ; then
                DIST=`cat /etc/SUSE-release | tr "\n" ' '| sed s/VERSION.*//`
                REV=`cat /etc/SUSE-release | tr "\n" ' ' | sed s/.*=\ //`
        elif [ -f /etc/mandrake-release ] ; then
                DIST='Mandrake'
                PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
                REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/debian_version ] ; then
                #DIST="Debian `cat /etc/debian_version`"
                DIST="Debian"
        fi

}

log ()
{
  "$@" 2>&1 | tee -a ${LOGFILE}
}


function pause(){
   read -p "$*"
}

function help {
cat <<USAGE
 USAGE: This script expects three arguments:(DCHQ Server Key), (DCHQ Server), (DCHQ port). for example:
 $0 7807f33e-501e-46a0-a4f9-762e22dbd3e9 52.16.21.157 32784
USAGE
}

function deb_docker_install(){
   echo "Starting installation, please wait this will take some time..."
   wget -qO- https://get.docker.com/ | sh
}

function rpm_docker_install() {
   echo "Installing docker..."
   yum install -y docker
   systemctl daemon-reload
   systemctl start docker
   systemctl enable docker
}

function oracle_docker_install() {
	echo "Installing docker on Oracle Linux..."
	sed -i "13s|0|1|g" /etc/yum.repos.d/public-yum-ol6.repo
	#yum install -y  yum-config-manager
	#yum-config-manager --enable public_ol6_addons
	yum install -y docker
	service docker start
	chkconfig docker on
}

function redhat_docker_install() {
   echo "Installing docker on Red Hat..."
tee /etc/yum.repos.d/docker.repo <<-EOF
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/7
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF
   yum install -y docker-engine
   service docker start
   chkconfig docker on
} 


# There must be 1 argument to the script.
function script_arg_check() {
if [ "$SHELL_VAR_COUNT" -ne 3 ]; then
  -h;
  exit 1
fi
}

function dchq_docker_cred_setup() {

cat << DCHQ_CRED_FILE > ${DOCKER_CRED_FILE}

{
        "https://index.docker.io/v1/": {
                "auth": "ZGNocTpEQ0hRMSE=",
                "email": "amjad@dchq.io"
        }
}

DCHQ_CRED_FILE

}

function dchq_pull_images() {
	echo "Pulling DCHQ images from Docker Hub, please wait.."
	docker pull dchq/dchq-on-premise-v4-postgres:${DCHQ_TAG}
	docker pull dchq/dchq-on-premise-v4-solr:${DCHQ_TAG}
	docker pull dchq/dchq-on-premise-v4-rabbitmq:${DCHQ_TAG}
        docker pull dchq/dchq-on-premise-v4-redis:${DCHQ_TAG}
	docker pull dchq/dchq-on-premise-v4-tomcat:${DCHQ_TAG}
	docker pull dchq/dchq-on-premise-v4-nginx:${DCHQ_TAG}
	docker pull dchq/ubuntu:latest
}

function dchq_stop_images() {
        echo "Stoping old DCHQ containers"
        for container in $DCHQ_CONTAINERS; do
                docker stop $container >/dev/null 2>&1
                docker rm $container >/dev/null 2>&1
        done
}

function dchq_run_images() {
	echo "Running DCHQ images..."
	echo "Running Ubuntu container to create RabbitMQ certificates"
	mkdir -p /opt/dchq/cache/rabbitmq1
	cd /opt/dchq/cache/rabbitmq1/
	wget https://www.dropbox.com/s/cgysgvtb3ap2dds/rabbit-ssl.sh?dl=1 -O rabbit-ssl.sh
	chmod +x rabbit-ssl.sh
	docker run -d -t --name dchq-ubuntu -v /opt/dchq/cache/rabbitmq1:/opt/dchq/cache/rabbitmq1 dchq/ubuntu:latest
	docker exec dchq-ubuntu /opt/dchq/cache/rabbitmq1/rabbit-ssl.sh
	docker stop dchq-ubuntu
	docker rm dchq-ubuntu
	docker run --restart=always --name dchq-postgres -v /opt/dchq/postgres/data:/var/lib/postgresql/data  --log-driver=syslog --log-opt tag="dchq_postgres" -e POSTGRES_USER=dchq -e POSTGRES_PASSWORD=${DCHQ_POSTGRES_PASSWORD} -e POSTGRES_DB=dchq -e POSTGRES_PORT=5432 -d dchq/dchq-on-premise-v4-postgres:${DCHQ_TAG}
	docker run -u root --restart=always --log-driver=syslog --log-opt tag="dchq_rabbitmq" -p 5671:5671 -p 15671:15671 --name dchq-rabbitmq -v /opt/dchq/cache/rabbitmq1:/opt/dchq/cache/rabbitmq1 -e RABBITMQ_PORT=5671 -e RABBITMQ_VH=dchq -e RABBITMQ_USERNAME=dchq_admin -e RABBITMQ_PASSWORD=${DCHQ_RABBITMQ_PASSWORD} -e RABBITMQ_NODENAME=rabbit -e RABBITMQ_SSL_CERT_FILE=/opt/dchq/cache/rabbitmq1/server/cert.pem -e RABBITMQ_SSL_KEY_FILE=/opt/dchq/cache/rabbitmq1/server/key.pem -e RABBITMQ_SSL_CA_FILE=/opt/dchq/cache/rabbitmq1/dchqca/cacert.pem -d dchq/dchq-on-premise-v4-rabbitmq:${DCHQ_TAG}
	docker run --restart=always --name dchq-solr --log-driver=syslog --log-opt tag="dchq_solr" -e SOLR_PORT=8983 -d dchq/dchq-on-premise-v4-solr:${DCHQ_TAG}
	docker run --restart=always --name dchq-redis --log-driver=syslog --log-opt tag="dchq_redis" -e REDIS_PORT=6379 -d dchq/dchq-on-premise-v4-redis:${DCHQ_TAG}
        echo "Please wait 60 seconds while the containers are starting..."
	sleep 60
	RABBITMQ_ID=$(docker ps --filter="name=dchq-rabbitmq"|grep 0.0.0.0|awk '{print $1}')
	RABBITMQ_PORT_HOST=$(docker port ${RABBITMQ_ID} 5671)
	RABBITMQ_PORT=${RABBITMQ_PORT_HOST##0.0.0.0:}
	docker restart dchq-rabbitmq
	sleep 10
	docker exec dchq-rabbitmq bash /dchq/init.sh ${DCHQ_RABBITMQ_PASSWORD}
	docker run --restart=always --name dchq-tomcat --log-driver=syslog --log-opt tag="dchq_tomcat" --link dchq-solr:dchq-solr --link dchq-postgres:dchq-postgres --link dchq-rabbitmq:dchq-rabbitmq --link dchq-redis:dchq-redis \
		-e spring.rabbitmq.ssl.enabled=true \
                -e spring.redis.host=dchq-redis \
                -e spring.redis.port=6379 \
                -e spring.rabbitmq.host=dchq-rabbitmq \
		-e spring.data.solr.host=http://dchq-solr:8983/solr \
		-e spring.rabbitmq.port=5671 \
		-e spring.rabbitmq.virtualHost=dchq \
		-e spring.rabbitmq.username=dchq_admin \
		-e spring.rabbitmq.password=${DCHQ_RABBITMQ_PASSWORD} \
		-e spring.datasource.password=${DCHQ_POSTGRES_PASSWORD} \
		-e spring.datasource.username=dchq \
		-e spring.datasource.driver-class-name=org.postgresql.Driver \
		-e spring.datasource.url=jdbc:postgresql://dchq-postgres:5432/dchq \
		-e spring.mail.host=${DCHQ_SMTP_HOST} \
		-e spring.mail.port=${DCHQ_SMTP_PORT} \
		-e spring.mail.username=${DCHQ_SMTP_USERNAME} \
		-e spring.mail.password=${DCHQ_SMTP_PASSWORD} \
		-e spring.mail.properties.mail.smtp.auth=${DCHQ_SMTP_AUTH} \
		-e spring.mail.properties.mail.smtp.socketFactory.port=${DCHQ_SMTP_SOCKET_PORT} \
		-e spring.mail.properties.mail.smtp.starttls.enable=true \
		-e spring.mail.properties.mail.smtp.socketFactory.class=javax.net.ssl.SSLSocketFactory \
		-e spring.mail.properties.mail.smtp.socketFactory.fallback=false \
		-e dchq.email.from=${DCHQ_EMAIL_FROM} \
                -e dchq.email.bcc=${DCHQ_EMAIL_BCC} \
		-e dchq.email.failure.to=${DCHQ_EMAIL_FAILURE_TO} \
		-d dchq/dchq-on-premise-v4-tomcat:${DCHQ_TAG}
	echo "Please wait 60 seconds while the setup is completed..."
	sleep 80
	docker restart dchq-tomcat
	sleep 80
	docker run --name dchq-nginx --restart=always --log-driver=syslog --log-opt tag="dchq_nginx" --link dchq-tomcat -d -t -p ${NGINX_SSL_PORT}:443 -v /opt/dchq/nginx/conf.d:/etc/nginx/conf.d -v /opt/dchq/nginx/ssl:/etc/ssl/certs dchq/dchq-on-premise-v4-nginx:${DCHQ_TAG}
}


function install_all {
  check_distro

  if [ ${DIST} == "Debian" ]; then
	echo "Linux Debian distribution detected..."
  	which docker
   	DOCKER_EXISTS="$?"
  	if [ ${DOCKER_EXISTS} -eq 1 ]; then 
		deb_docker_install
	fi
	if [ $HTTP_PROXY_ENABLED == "true" ]; then
		deb_proxy_setup
	fi

  fi

  if [ ${DIST} == "RedHat" ]; then
	echo "Linux RedHat distribution detected..."
	which docker
   	DOCKER_EXISTS="$?"
  	if [ ${DOCKER_EXISTS} -eq 1 ]; then 
		yum-config-manager --enable rhui-REGION-rhel-server-extras
		redhat_docker_install
	fi
	if [ $HTTP_PROXY_ENABLED == "true" ]; then
		rpm_proxy_setup
	fi

  fi
  
  if [ ${DIST} == "Oracle" ]; then
	echo "Oracle Linux distribution detected..."
	which docker
   	DOCKER_EXISTS="$?"
  	if [ ${DOCKER_EXISTS} -eq 1 ]; then 
		oracle_docker_install
	fi
	if [ $HTTP_PROXY_ENABLED == "true" ]; then
		rpm_proxy_setup
	fi

  fi  

  if [ ${DIST} == "CentOS" ]; then
	echo "Linux CentOS distribution detected..."
	which docker
   	DOCKER_EXISTS="$?"
  	if [ ${DOCKER_EXISTS} -eq 1 ]; then 
		rpm_docker_install
	fi
	if [ $HTTP_PROXY_ENABLED == "true" ]; then
		rpm_proxy_setup
	fi
  fi

  service docker restart
  dchq_docker_cred_setup
  dchq_stop_images
  dchq_pull_images
  dchq_run_images

}


function deb_proxy_setup() {
        if [ $PROXY_AUTH == "true" ]; then
                echo export HTTP_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTP_PROXY_HOST:$HTTP_PROXY_PORT" >> $DEB_DOCKER_CONFIG
                echo export HTTPS_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT" >> $DEB_DOCKER_CONFIG
        else
                echo export HTTP_PROXY="http://$HTTP_PROXY_HOST:$HTTP_PROXY_PORT" >> $DEB_DOCKER_CONFIG
                echo export HTTPS_PROXY="http://$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT" >> $DEB_DOCKER_CONFIG
        fi
}

function rpm_proxy_setup() {
        if [ $PROXY_AUTH == "true" ]; then
                echo export HTTP_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTP_PROXY_HOST:$HTTP_PROXY_PORT" >> $RPM_DOCKER_CONFIG
                echo export HTTPS_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT" >> $RPM_DOCKER_CONFIG
        else
                echo export HTTP_PROXY="http://$HTTP_PROXY_HOST:$HTTP_PROXY_PORT" >> $RPM_DOCKER_CONFIG
                echo export HTTPS_PROXY="http://$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT" >> $RPM_DOCKER_CONFIG
        fi  
}

function get_smtp_settings() {
	read -p "What is the SMTP server hostname/IP: " DCHQ_SMTP_HOST
	read -p "What is the SMTP server port: (usually its 25 or 465 for TLS/SSL) " DCHQ_SMTP_PORT
	while true; do
		read -p "Does your SMTP server require authentication: " yn
		case $yn in
       		 [Yy]* ) read -p "What is the SMTP username: " DCHQ_SMTP_USERNAME; read -p "What is the SMTP password: " DCHQ_SMTP_PASSWORD; DCHQ_SMTP_AUTH=true; break;;
       		 [Nn]* ) break;;
       		 * ) echo "Please answer yes or no.";;
    		esac
	done
	read -p "What should be the sending email address?" DCHQ_EMAIL_FROM
        read -p "What should be the BCC email address for new user sign ups?" DCHQ_EMAIL_BCC
	read -p "What email address should receive failed issues?" DCHQ_EMAIL_FAILURE_TO
}

function get_proxy_settings() {
	HTTP_PROXY_ENABLED=true
	read -p "What is the HTTP proxy server hostname/IP: " HTTP_PROXY_HOST
	read -p "What is the HTTP proxy server port: " HTTP_PROXY_PORT
	read -p "What is the HTTPS proxy server hostname/IP: " HTTPS_PROXY_HOST
	read -p "What is the HTTPS proxy server port: " HTTPS_PROXY_PORT
	while true; do
		read -p "Does your proxy server require authentication: [Y|N] " yn
		case $yn in
       		 [Yy]* ) read -p "What is the proxy username: " PROXY_USERNAME; read -p "What is the proxy password: " PROXY_PASSWORD; PROXY_AUTH=true; break;;
       		 [Nn]* ) break;;
       		 * ) echo "Please answer yes or no.";;
    		esac
	done
	if [ "$PROXY_AUTH" == "true" ]; then 
		export HTTP_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTP_PROXY_HOST:$HTTP_PROXY_PORT"
		export HTTPS_PROXY="http://$PROXY_USERNAME:$PROXY_PASSWORD@$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT"
	else
		export HTTP_PROXY="http://$HTTP_PROXY_HOST:$HTTP_PROXY_PORT"
		export HTTPS_PROXY="http://$HTTPS_PROXY_HOST:$HTTPS_PROXY_PORT"
	fi
}

function create_nginx_ssl() {
	read -p "What is the SSL port you would like to use for Nginx: (the default value is 443) " NGINX_SSL_PORT
	if [[ -z "$NGINX_SSL_PORT" ]]; then
   		export NGINX_SSL_PORT=443
		echo "Nginx SSL port will be: " ${NGINX_SSL_PORT}
	else
		echo "Nginx SSL port will be: " ${NGINX_SSL_PORT}
	fi
        if ls /opt/dchq/nginx/ssl/* 1> /dev/null 2>&1; then
                echo "SSL certificate already exists"
                while true; do
		read -p "Would you like to replace the SSL certificate that already exists in /opt/dchq/nginx/ssl/: " yn
		case $yn in
       		 [Yy]* ) echo "Creating SSL certificate"; openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/dchq/nginx/ssl/nginx.key -out /opt/dchq/nginx/ssl/nginx.crt; break;;
       		 [Nn]* ) break;;
       		 * ) echo "Please answer yes or no.";;
    		esac
	done

        else
                echo "Creating SSL certificate"
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/dchq/nginx/ssl/nginx.key -out /opt/dchq/nginx/ssl/nginx.crt
        fi
}

function configure_nginx_conf() {

mkdir -p /opt/dchq/nginx/conf.d

cat <<'EOF'>> /opt/dchq/nginx/conf.d/default.conf
upstream backend_hosts {
server dchq-tomcat:8080;

}
    server {
        listen     443 ssl;
        ssl  on;
                
        location / {
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_pass http://backend_hosts/;
        }
        ssl_certificate         /etc/ssl/certs/nginx.crt;
        ssl_certificate_key     /etc/ssl/certs/nginx.key;
        ssl_protocols           TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers             HIGH:!aNULL:!MD5;
        ssl_trusted_certificate /etc/ssl/certs/nginx.crt;

    }    
EOF

}



############################################
#  main
############################################

if [ $( id -u ) -ne 0 ]; then
    echo "ERROR: $0 Must be run as root, script terminating." ;exit 2
fi

#script_arg_check
echo "This script installs DCHQ On-Premise software on Enterprise/Cloud Systems"
pause "Press [Enter] key to continue... CTRL-C to exit."

while true; do
    read -p "Would you like to create a self-signed SSL certificate for Nginx now? [Y|N] " yn
    case $yn in
        [Yy]* ) create_nginx_ssl; break;;
        [Nn]* ) "Please make sure that your Nginx SSL certificate is in the /opt/dchq/nginx/ssl/ directory. Please exit this installation and place the certificate before proceeding."; break;;
        * ) echo "Please answer yes or no.";;
    esac
done

while true; do
    read -p "Would you like to configure an email server (SMTP settings)? [Y|N] " yn
    case $yn in
        [Yy]* ) get_smtp_settings; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

while true; do
    read -p "Would you like to configure an HTTP proxy for Docker? [Y|N] " yn
    case $yn in
        [Yy]* ) get_proxy_settings; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done



echo "Starting installation, please wait..."

configure_nginx_conf

check_distro
if [ "${DIST}" == "Oracle" ]; then
	echo "Oracle Linux distribution detected..."
	else 
	/bin/yum -y install bind-utils curl || /usr/bin/apt-get update && /usr/bin/apt-get -y install dnsutils curl
fi

INTERNAL_SERVER_IP=$(hostname -I|awk '{print $1}')
EXTERNAL_SERVER_IP=$(curl --connect-timeout 20 -s http://ifconfig.co/)
CURL_RESULT=$?
if [ ${CURL_RESULT} -ne 0 ]; then
	EXTERNAL_SERVER_IP=$(dig @resolver1.opendns.com myip.opendns.com +short)
	CURL_RESULT=$?
	if [ ${CURL_RESULT} -ne 0 ]; then
		EXTERNAL_SERVER_IP=$(curl --connect-timeout 20 -s http://ifconfig.me/)
		CURL_RESULT=$?
		if [ ${CURL_RESULT} -ne 0 ]; then
			EXTERNAL_SERVER_IP=127.0.0.1
		fi
	fi
fi

DCHQ_CONNECT_IP=$EXTERNAL_SERVER_IP

install_all
TOMCAT_ID=$(docker ps --filter="name=dchq-tomcat"|grep 0.0.0.0|awk '{print $1}')
TOMCAT_PORT=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{(index $conf 0).HostPort}} {{end}}'  ${TOMCAT_ID})



echo ""
echo "----------------------------------------------------"
echo "Installation complete, please use these credentials:"
echo "Database password is" $DCHQ_POSTGRES_PASSWORD
echo "RabbitMQ password is" $DCHQ_RABBITMQ_PASSWORD
echo "username=admin@dchq.io, password=admin123"
echo "to connect to the following URL:"
echo "https://${INTERNAL_SERVER_IP}:${NGINX_SSL_PORT}"
if [ $HTTP_PROXY_ENABLED == "false" ]; then
	echo "or using the public IP:"
	echo "https://${EXTERNAL_SERVER_IP}:${NGINX_SSL_PORT}"
fi
echo "----------------------------------------------------"
echo ""
echo "Enjoy DCHQ On-Premise"