# Azure IoT Hub con SAS Token y MQTT

Proyecto práctico de seguridad IoT sobre autenticación de dispositivos en **Azure IoT Hub** mediante **SAS Token**, publicación MQTT y actualización de propiedades en el **Device Twin**.

El objetivo del proyecto es demostrar, de forma reproducible y defendible en entrevista, cómo se registra un dispositivo IoT en Azure, cómo se genera un token SAS a partir de una clave simétrica y cómo se comunica el dispositivo con IoT Hub usando MQTT sobre TLS.

---

## Índice

- [Objetivos](#objetivos)
- [Arquitectura del laboratorio](#arquitectura-del-laboratorio)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Requisitos previos](#requisitos-previos)
- [1. Creación del IoT Hub](#1-creación-del-iot-hub)
- [2. Registro del dispositivo](#2-registro-del-dispositivo)
- [3. Generación del SAS Token](#3-generación-del-sas-token)
- [4. Conexión MQTT con Mosquitto](#4-conexión-mqtt-con-mosquitto)
- [5. Actualización de propiedades reported del Device Twin](#5-actualización-de-propiedades-reported-del-device-twin)
- [6. Recepción de propiedades desired](#6-recepción-de-propiedades-desired)
- [Buenas prácticas de seguridad](#buenas-prácticas-de-seguridad)
- [Problemas habituales y troubleshooting](#problemas-habituales-y-troubleshooting)
- [Posibles mejoras](#posibles-mejoras)
- [Referencias](#referencias)

---

## Objetivos

Este laboratorio cubre los siguientes puntos:

- Crear un **Azure IoT Hub** en un grupo de recursos.
- Registrar un dispositivo IoT mediante autenticación con **clave simétrica**.
- Generar manualmente un **SAS Token** firmado con HMAC-SHA256.
- Conectarse a Azure IoT Hub mediante **MQTT sobre TLS**.
- Publicar datos en el **Device Twin**, concretamente en propiedades `reported`.
- Suscribirse a cambios de propiedades `desired` enviados desde Azure hacia el dispositivo.
- Analizar implicaciones de seguridad: caducidad de tokens, rotación de claves y protección de secretos.

---

## Arquitectura del laboratorio

```text
+---------------------+          MQTT/TLS 8883           +----------------------+
|                     |  SAS Token como password MQTT    |                      |
|  Cliente local      +--------------------------------->|  Azure IoT Hub       |
|  Mosquitto / Python |                                  |                      |
|                     |<---------------------------------+  Device Twin         |
+---------------------+      Desired properties          +----------------------+
          |
          | Generación local
          v
+---------------------+
|  SAS Token          |
|  HMAC-SHA256        |
|  Device key + URI   |
+---------------------+
```

Flujo resumido:

1. Azure IoT Hub registra un dispositivo con dos claves simétricas: primaria y secundaria.
2. El dispositivo no envía la clave directamente, sino un **SAS Token temporal**.
3. El token se usa como contraseña en la conexión MQTT.
4. El dispositivo publica propiedades `reported` en el Device Twin.
5. Azure puede enviar propiedades `desired`, que el dispositivo recibe mediante suscripción MQTT.

---

## Tecnologías utilizadas

- **Microsoft Azure IoT Hub**
- **Device Twin**
- **SAS Token**
- **MQTT v3.1.1**
- **TLS**
- **Mosquitto clients**: `mosquitto_pub` y `mosquitto_sub`
- **Python 3**
- **HMAC-SHA256**
- **Base64**
- **URL encoding**

---

## Requisitos previos

- Cuenta de Azure con permisos para crear recursos.
- Azure IoT Hub creado en un grupo de recursos.
- Un dispositivo registrado en IoT Hub.
- Python 3 instalado.
- Cliente Mosquitto instalado.
- Certificado raíz público requerido para validar TLS contra Azure IoT Hub.

En Linux:

```bash
sudo apt update
sudo apt install mosquitto-clients python3
```

En Windows, Mosquitto puede instalarse desde el instalador oficial o mediante un gestor de paquetes como Chocolatey:

```powershell
choco install mosquitto
```

---

## 1. Creación del IoT Hub

Desde el portal de Azure:

1. Acceder a **Create a resource**.
2. Buscar **IoT Hub**.
3. Seleccionar el grupo de recursos o crear uno nuevo.
4. Definir el nombre del IoT Hub.
5. Seleccionar un tier adecuado para laboratorio, por ejemplo **Free tier**.
6. Mantener conectividad pública para simular un dispositivo conectado desde Internet o desde el equipo local.
7. Revisar la configuración y crear el recurso.

<img width="745" height="543" alt="image" src="https://github.com/user-attachments/assets/9c6077ec-f497-472e-9ee6-0a3ef5aa12a5" />

Para un entorno real, habría que revisar con más detalle la exposición de red, integración con redes privadas, políticas de acceso, monitorización y logging.

---

## 2. Registro del dispositivo

Dentro del IoT Hub:

1. Ir a **Device management > Devices**.
2. Crear un nuevo dispositivo.
3. Definir un `Device ID`, por ejemplo:

```text
DevGeorge_1998
```

4. Seleccionar autenticación mediante **Symmetric key**.
5. Guardar el dispositivo.

Azure generará:

- Primary key.
- Secondary key.
- Primary connection string.
- Secondary connection string.

<img width="412" height="548" alt="image" src="https://github.com/user-attachments/assets/0ab741c7-07c2-4617-a4e0-bb64f6eac081" />

La existencia de dos claves permite implementar rotación sin interrumpir completamente la conectividad: se puede usar una clave como activa y mantener la otra como fallback durante el proceso de rotación.

---

## 3. Generación del SAS Token

Azure IoT Hub permite autenticar dispositivos mediante tokens SAS con caducidad temporal. El formato general es:

```text
SharedAccessSignature sr={resource_uri}&sig={signature}&se={expiry}
```

Donde:

- `sr`: URI del recurso codificada en URL.
- `sig`: firma HMAC-SHA256 codificada en Base64 y URL encoded.
- `se`: fecha de expiración en formato Unix epoch.

Ejemplo de URI de recurso:

```text
<iot-hub-name>.azure-devices.net/devices/<device-id>
```

### Script de ejemplo

Archivo: `scripts/generate_sas_token.py`

```python
import base64
import hashlib
import hmac
import os
import time
import urllib.parse


def generate_sas_token(resource_uri: str, key: str, expiry_seconds: int = 3600) -> str:
    """Generate an Azure IoT Hub SAS token for a device.

    Args:
        resource_uri: IoT Hub device URI, for example
            my-hub.azure-devices.net/devices/my-device.
        key: Device primary or secondary key in Base64.
        expiry_seconds: Token lifetime in seconds.

    Returns:
        SAS token string.
    """
    expiry = int(time.time()) + expiry_seconds
    encoded_uri = urllib.parse.quote(resource_uri, safe="")
    string_to_sign = f"{encoded_uri}\n{expiry}"

    decoded_key = base64.b64decode(key)
    signature = hmac.new(
        decoded_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    encoded_signature = urllib.parse.quote(base64.b64encode(signature))

    return (
        f"SharedAccessSignature sr={encoded_uri}"
        f"&sig={encoded_signature}"
        f"&se={expiry}"
    )


if __name__ == "__main__":
    resource_uri = os.environ["IOTHUB_RESOURCE_URI"]
    device_key = os.environ["IOTHUB_DEVICE_KEY"]
    token = generate_sas_token(resource_uri, device_key)
    print(token)
```

Uso recomendado con variables de entorno:

```bash
export IOTHUB_RESOURCE_URI="<iot-hub-name>.azure-devices.net/devices/<device-id>"
export IOTHUB_DEVICE_KEY="<device-primary-or-secondary-key>"
python3 scripts/generate_sas_token.py
```

En PowerShell:

```powershell
$env:IOTHUB_RESOURCE_URI="<iot-hub-name>.azure-devices.net/devices/<device-id>"
$env:IOTHUB_DEVICE_KEY="<device-primary-or-secondary-key>"
python scripts/generate_sas_token.py
```

El token generado debe renovarse antes de su expiración.

---

## 4. Conexión MQTT con Mosquitto

Descargar el certificado raíz usado para validar la conexión TLS:

```bash
curl -O https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem
```

Parámetros principales de conexión:

```text
Host:       <iot-hub-name>.azure-devices.net
Port:       8883
Client ID:  <device-id>
Username:   <iot-hub-name>.azure-devices.net/<device-id>/?api-version=2018-06-30
Password:   <sas-token>
TLS CA:     DigiCertGlobalRootG2.crt.pem
```

---

## 5. Actualización de propiedades reported del Device Twin

Las propiedades `reported` representan el estado que el dispositivo informa a Azure.

Topic MQTT para actualizar propiedades `reported`:

```text
$iothub/twin/PATCH/properties/reported/?$rid=<request-id>
```

Ejemplo con `mosquitto_pub`:

```bash
mosquitto_pub \
  -h "<iot-hub-name>.azure-devices.net" \
  -p 8883 \
  -t '$iothub/twin/PATCH/properties/reported/?$rid=1' \
  -i "<device-id>" \
  -u "<iot-hub-name>.azure-devices.net/<device-id>/?api-version=2018-06-30" \
  -P "<sas-token>" \
  -m '{"temperature": 38.5}' \
  --cafile ./DigiCertGlobalRootG2.crt.pem \
  -d \
  -V mqttv311 \
  -q 1
```

En Windows puede ser necesario usar comillas dobles en el topic y escapar correctamente los caracteres especiales:

```powershell
mosquitto_pub `
  -h "<iot-hub-name>.azure-devices.net" `
  -p 8883 `
  -t "`$iothub/twin/PATCH/properties/reported/?`$rid=1" `
  -i "<device-id>" `
  -u "<iot-hub-name>.azure-devices.net/<device-id>/?api-version=2018-06-30" `
  -P "<sas-token>" `
  -m '{"temperature": 38.5}' `
  --cafile ./DigiCertGlobalRootG2.crt.pem `
  -d `
  -V mqttv311 `
  -q 1
```

<img width="951" height="173" alt="image" src="https://github.com/user-attachments/assets/5e56012e-7557-4973-bf70-aaa1b0d9629d" />

Tras la publicación, el valor debe aparecer en el Device Twin dentro de:

```json
{
  "properties": {
    "reported": {
      "temperature": 38.5
    }
  }
}
```

<img width="555" height="661" alt="image" src="https://github.com/user-attachments/assets/4135ff83-49ef-4abd-aa55-922607750f16" />

---

## 6. Recepción de propiedades desired

Las propiedades `desired` representan el estado objetivo configurado desde el backend o desde Azure para que el dispositivo actúe en consecuencia.

Topic MQTT para recibir cambios de propiedades `desired`:

```text
$iothub/twin/PATCH/properties/desired/#
```

Ejemplo con `mosquitto_sub`:

```bash
mosquitto_sub \
  -h "<iot-hub-name>.azure-devices.net" \
  -p 8883 \
  -t '$iothub/twin/PATCH/properties/desired/#' \
  -i "<device-id>" \
  -u "<iot-hub-name>.azure-devices.net/<device-id>/?api-version=2018-06-30" \
  -P "<sas-token>" \
  --cafile ./DigiCertGlobalRootG2.crt.pem \
  -d
```

<img width="951" height="162" alt="image" src="https://github.com/user-attachments/assets/d46bbdbf-dfb0-4612-965c-88f9ba148274" />

Si desde Azure se actualiza el Device Twin con una temperatura deseada:

```json
{
  "properties": {
    "desired": {
      "temperature": 40.7
    }
  }
}
```

El dispositivo debe recibir una notificación MQTT con el cambio.

<img width="738" height="371" alt="image" src="https://github.com/user-attachments/assets/9f6b4aaa-d176-4d82-8cce-f02ec130a154" />

---

## Buenas prácticas de seguridad

- Usar tokens SAS con expiración corta.
- Automatizar la renovación del token antes de su caducidad.
- Rotar periódicamente la primary key y secondary key.
- Usar una clave secundaria como mecanismo de continuidad durante la rotación.
- Usar TLS y validar correctamente el certificado del broker.
- Aplicar el principio de mínimo privilegio en políticas de acceso.
- Para entornos productivos, valorar autenticación con certificados X.509 en lugar de claves simétricas.
- Monitorizar errores de autenticación, desconexiones y actividad anómala del dispositivo.
- Separar configuración sensible mediante variables de entorno o un gestor de secretos.

---

## Problemas habituales y troubleshooting

### Error de autenticación MQTT

Posibles causas:

- SAS Token expirado.
- `sr` del token no coincide exactamente con el IoT Hub y el Device ID.
- Uso de una key incorrecta.
- Username MQTT mal formado.
- Device ID incorrecto.
- Token truncado o con caracteres mal escapados.

### Error TLS o fallo de certificado

Posibles causas:

- Falta el certificado raíz.
- Ruta incorrecta en `--cafile`.
- Reloj del sistema desincronizado.
- Inspección TLS corporativa o proxy intermedio.

### No se actualiza el Device Twin

Posibles causas:

- Topic incorrecto.
- Request ID mal escapado en Windows.
- Publicación en topic de telemetría en lugar de topic de twin.
- Payload JSON mal formado.
- El token no tiene permisos válidos para ese dispositivo.

---

## Posibles mejoras

- Crear un script Python que publique telemetría periódica simulando sensores.
- Añadir renovación automática del SAS Token.
- Usar Azure IoT SDK en Python o Node.js.
- Comparar autenticación mediante SAS Token frente a certificados X.509.
- Integrar logs con Azure Monitor.
- Añadir alertas ante desconexiones o valores anómalos.
- Crear una simulación de dispositivo vulnerable y documentar riesgos de exposición de claves.
- Añadir GitHub Actions para comprobar linting del código Python.
- Documentar un modelo de amenazas básico con STRIDE.

---

## Referencias

- Azure IoT Hub - autenticación y autorización con SAS: https://learn.microsoft.com/es-es/azure/iot-hub/authenticate-authorize-sas
- Azure IoT Hub - comunicación MQTT: https://learn.microsoft.com/es-es/azure/iot-hub/iot-mqtt-connect-to-iot-hub
- Azure IoT Hub - Device Twins: https://learn.microsoft.com/es-es/azure/iot-hub/how-to-device-twins
- Tutorial MQTT con Azure IoT Hub: https://learn.microsoft.com/es-es/azure/iot-hub/tutorial-use-mqtt
