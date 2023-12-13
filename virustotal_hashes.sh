#!/bin/bash

API_KEY=""
HASHES=""
OUTPUT="resultados.csv"

for arg in "$@"; do
    case "$arg" in
        API_KEY=*) API_KEY="${arg#*=}" ;;
        HASHES=*) HASHES="${arg#*=}" ;;
    esac
done

echo "Leyendo el archivo de hashes..."

get_new_apikey() {
    while true; do
        echo -e "\033[0;31mQuota Excedida | Credencial error. Esperando otra API_KEY para continuar el análisis\033[0m"

        # Esperar por una nueva API_KEY
        NEW_API_KEY=$(read -p "Por favor, ingresa una nueva API_KEY para continuar: ")
        $NEW_API_KEY
        API_KEY="$NEW_API_KEY"

        RESPONSE=$(curl -sS --request GET \
            --url "https://www.virustotal.com/api/v3/files/${HASH}" \
            --header "x-apikey: ${API_KEY}")

        STATUS=$(echo "$RESPONSE" | jq -r '.error.code')

        if [[ $STATUS != "QuotaExceededError" || $STATUS != "WrongCredentialsError" || $STATUS !=  "AuthenticationRequiredError" ]]; then
            API_KEY="$NEW_API_KEY"
            break
        fi
    done
}

while IFS= read -r HASH; do
    echo -e "\033[0;32mProbando la URL con hash: ${HASH}\033[0m"
    RESPONSE=$(curl -sS --request GET \
        --url "https://www.virustotal.com/api/v3/files/${HASH}" \
        --header "x-apikey: ${API_KEY}")
           STATUS=$(echo "$RESPONSE" | jq -r '.error.code')
    NAME=$(echo "$RESPONSE" | jq -r '.data.attributes.meaningful_name')
    REPUTATION=$(echo "$RESPONSE" | jq -r '.data.attributes.reputation')

    if [[ $STATUS == "QuotaExceededError" || $STATUS == "WrongCredentialsError" || $STATUS == "AuthenticationRequiredError" ]]; then
get_new_apikey

if [ -z "$API_KEY" ]; then
    echo "Se requiere una API_KEY válida para continuar. Saliendo del programa."
    exit 1
    fi
fi
    echo "Response status code: $STATUS"
    echo "Meaningful name: $NAME"

    if [[ $STATUS == "NotFoundError" ]]; then
        echo -e "\033[0;34mEl Hash: ${HASH} no tiene coincidencia\033[0m"
        echo "${HASH},Sin coincidencias,N/A" >>"$OUTPUT"
    elif [[ $STATUS == "null" ]]; then
        if [[ $NAME == "0" ]]; then
            echo -e "\033[0;34mEl Hash: ${HASH} tiene coincidencia\033[0m ${REPUTATION}"
            echo "${HASH},${NAME},${REPUTATION},NO MALICIOSO" >>"$OUTPUT"
        else
            echo -e "\033[0;33mEl Hash: ${HASH} tiene coincidencia de nombre\033[0:34m ${REPUTATION}"
            echo "${HASH},${NAME},${REPUTATION},MALICIOSO" >>"$OUTPUT"
        fi
    fi
done <"$HASHES"
exit 0
