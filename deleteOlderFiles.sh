#!/bin/bash

find /o/app/oracle/admin/PROD/udump/* -mtime +1 -exec rm {} \; ----- borra archivos con mas de 1 día de antigüedad
