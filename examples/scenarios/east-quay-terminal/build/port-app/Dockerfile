FROM php:8.2-apache@sha256:1bc4115a5528326425f1f59846fc7879d7d3843da9905b42931755ac4d4b29bc
RUN docker-php-ext-install mysqli pdo_mysql \
    && printf 'ServerName port-app\n' > /etc/apache2/conf-available/servername.conf \
    && a2enconf servername
COPY app/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
