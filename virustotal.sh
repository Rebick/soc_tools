#!/bin/bash
# Colores
COLOR_GREEN='\033[0;32m' COLOR_PURPLE='\033[0;35m' COLOR_ORANGE='\033[0;33m' COLOR_RED='\033[0;31m' COLOR_BLUE='\033[0;34m' COLOR_RESET='\033[0m'
# Variable para verificar si se encontraron coincidencias
encontrado=0
# Almacena las IPs procesadas
ips_procesadas=()
# Función para agregar una IP al archivo /var/www/html/ip.txt
function agregar_ip {
  local ip="$1"
  echo "$ip" >> /var/www/html/ip.txt
}
# Leer cada línea del archivo ips.txt
while IFS=, read -r _ ip _; do
  # Verificar si la IP ya ha sido procesada
  if [[ " ${ips_procesadas[@]} " =~ " $ip " ]]; then
    continue
  fi
  # Agregar la IP actual a la lista de IPs procesadas
  ips_procesadas+=("$ip")
  if grep -Fxq "$ip" <(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' /var/www/html/ip.txt); then
    echo -e "${COLOR_BLUE}La IP está en el archivo.${COLOR_RESET}"
  else
    # Realizar la solicitud HTTP y guardar la respuesta en una variable
    response=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
      -H "x-apikey: d4890d631dcb2e8c5546f17465456d0836c0c88eb2efe7ebd7483fc5d1137bdd")
    # Buscar el campo "last_analysis_stats" en la respuesta JSON
    if [[ $response =~ \"last_analysis_stats\":\ \{([^}]+) ]]; then
      last_analysis_stats="${BASH_REMATCH[1]}"
      # Buscar el valor de "Undetected"
      if [[ $last_analysis_stats =~ \"undetected\":\ ([0-9]+), ]]; then
        undetected="${BASH_REMATCH[1]}"
        # Verificar si el valor de "Undetected" es diferente de 88
        if [[ "$undetected" -ne 88 ]]; then
          # Buscar los campos que tengan un valor mayor o igual a 1
          if [[ $last_analysis_stats =~ \"malicious\":\ ([1-9][0-9]*),|\"suspicious\":\ ([1-9][0-9]*), ]]; then
            malicious="${BASH_REMATCH[1]}"
            suspicious="${BASH_REMATCH[2]}"
            # Verificar si alguno de los campos tiene un valor mayor o igual a 1
            if [[ "$malicious" -ge 1 || "$suspicious" -ge 1 ]]; then
              # Mostrar el resultado en colores y con números
              echo -e "${COLOR_GREEN}Se han encontrado coincidencias en${COLOR_RESET} ${COLOR_PURPLE}${ip}${COLOR_RESET}, valores - ${COLOR_ORANGE}Malicious: ${COLOR_RED}${malicious:-0}${COLOR_RESET}, ${COLOR_ORANGE}Suspicious:
${COLOR_RED}${suspicious:-0}${COLOR_RESET}, ${COLOR_ORANGE}Undetected: ${COLOR_RED}${undetected}${COLOR_RESET}"
              encontrado=1
              # Verificar si la IP está en el archivo /var/www/html/ip.txt
              if grep -Fxq "$ip" <(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' /var/www/html/ip.txt); then
                echo -e "${COLOR_BLUE}La IP está en el archivo.${COLOR_RESET}"
              else
                echo -e "${COLOR_RED}La IP no se encuentra en el archivo.${COLOR_RESET}"
                # Agregar la IP al archivo /var/www/html/ip.txt
                agregar_ip "$ip"
                echo -e "${COLOR_BLUE}La IP se agregó al archivo.${COLOR_RESET}"
              fi
            fi
          fi
        fi
      fi
    fi
  fi done < <(sort -u ips.txt)
# Verificar si no se encontraron coincidencias
if [[ "$encontrado" -eq 0 ]]; then
  echo -e "${COLOR_RED}No se han encontrado coincidencias en las IPs proporcionadas.${COLOR_RESET}" fi

