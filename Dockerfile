FROM fauria/vsftpd:latest

ENV PASV_ENABLE NO

COPY vsftpd.conf /etc/vsftpd


