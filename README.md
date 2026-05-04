# Solución — Laboratorio: Análisis de Tráfico de Red

**Wireshark · Nmap · Hexadecimal**

> **Entorno simulado** | IP Cliente: `192.168.1.10` | IP Objetivo: `10.0.0.99`
> Archivo de captura: `lab_traffic.pcap` — 54 paquetes

---

## Índice

1. [Ejercicio 1 — Credenciales FTP](#ejercicio-1)
2. [Ejercicio 2 — TCP 3-way Handshake](#ejercicio-2)
3. [Ejercicio 3 — Escaneo Nmap SYN](#ejercicio-3)
4. [Ejercicio 4 — Petición HTTP Completa](#ejercicio-4)
5. [Análisis Hexadecimal](#hexadecimal)
6. [Cuestionario Q5–Q12](#cuestionario)
7. [Referencia Rápida — Filtros y Comandos](#referencia)

---

## Ejercicio 1 — Credenciales FTP en Texto Plano

**Filtros Wireshark:**

```
ftp
frame contains "PASS"
```

### Sesión FTP capturada

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FLUJO FTP  (puerto 21)                           │
│                                                                     │
│   Cliente (192.168.1.10)         Servidor FTP                       │
│           │                           │                             │
│           │  ←── 220 FTP Server Ready ┤                             │
│           │      32 32 30 20 46 54 50…│                             │
│           │                           │                             │
│           ├── USER admin ──────────►  │  ⚠ TEXTO PLANO             │
│           │   55 53 45 52 20 61 64 6d │                             │
│           │   69 6e                   │                             │
│           │                           │                             │
│           │  ←── 331 Password required┤                             │
│           │      33 33 31 20 50 61 73…│                             │
│           │                           │                             │
│           ├── PASS s3cr3tP@ssw0rd ──► │  ⚠ CREDENCIAL EXPUESTA     │
│           │   50 41 53 53 20 73 33 63 │                             │
│           │   72 33 74 50 40 73 73 77 │                             │
│           │   30 72 64                │                             │
│           │                           │                             │
│           │  ←── 230 Login successful ┤                             │
│           │      32 33 30 20 4c 6f 67…│                             │
└─────────────────────────────────────────────────────────────────────┘
```

### Credenciales encontradas

| Campo                 | Valor                     |
| --------------------- | ------------------------- |
| **Usuario**     | `admin`                 |
| **Contraseña** | `s3cr3tP@ssw0rd`        |
| Protocolo             | FTP — puerto 21          |
| Cifrado               | ❌ Ninguno — texto plano |

### ¿Por qué es un riesgo?

Cualquier nodo en la ruta de red (router, switch, atacante en modo promiscuo) puede capturar las credenciales con un simple sniffer. No se requiere romper ningún cifrado porque no existe.

### Alternativas seguras

| Protocolo inseguro | Alternativa segura                  | Cifrado |
| ------------------ | ----------------------------------- | ------- |
| FTP (puerto 21)    | **SFTP** — SSH File Transfer | SSH/AES |
| FTP (puerto 21)    | **FTPS** — FTP over TLS      | TLS/SSL |
| FTP (puerto 21)    | **SCP** — Secure Copy        | SSH     |

---

## Ejercicio 2 — TCP 3-way Handshake

**Filtro Wireshark:**

```
tcp.flags.syn==1 && ip.dst==93.184.216.34
```

### Diagrama de la conexión

```
   192.168.1.10                           93.184.216.34
   (Cliente)                              (Servidor)
       │                                       │
       │  ①  SYN  ──────────────────────────►  │
       │       Flags = 0x002                   │
       │       Seq  = 1000                     │
       │       Ack  = 0                        │
       │                                       │
       │  ②  ◄──────────────────────  SYN-ACK  │
       │       Flags = 0x012                   │
       │       Seq  = 5000                     │
       │       Ack  = 1001  (Seq cliente + 1)  │
       │                                       │
       │  ③  ACK  ──────────────────────────►  │
       │       Flags = 0x010                   │
       │       Seq  = 1001                     │
       │       Ack  = 5001  (Seq servidor + 1) │
       │                                       │
       │  ✔  CONEXIÓN ESTABLECIDA              │
       │  ════════════════════════════════════ │
       │       Intercambio de datos (HTTP…)    │
```

### Tabla de paquetes

| Paso | Flags             | Hex       | Origen → Destino   | Seq  | Ack  |
| ---- | ----------------- | --------- | ------------------- | ---- | ---- |
| ①   | **SYN**     | `0x002` | Cliente → Servidor | 1000 | 0    |
| ②   | **SYN-ACK** | `0x012` | Servidor → Cliente | 5000 | 1001 |
| ③   | **ACK**     | `0x010` | Cliente → Servidor | 1001 | 5001 |

### Lógica de los números de secuencia

```
  SYN consume 1 número →  Seq=1000  implica   siguiente esperado = 1001
  Servidor responde:       Ack=1001  confirma  el SYN del cliente
  SYN-ACK consume 1    →  Seq=5000  implica   siguiente esperado = 5001
  Cliente confirma:        Ack=5001  confirma  el SYN-ACK del servidor
```

---

## Ejercicio 3 — Escaneo Nmap SYN

**Filtros Wireshark para correlacionar el escaneo:**

```
# SYNs enviados por el escáner
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.1.10

# Puertos ABIERTOS  →  respuesta SYN-ACK
tcp.flags==0x012 && ip.src==10.0.0.99

# Puertos CERRADOS  →  respuesta RST
tcp.flags.reset==1 && ip.src==10.0.0.99

# Puertos FILTRADOS →  retransmisiones
tcp.analysis.retransmission && ip.src==192.168.1.10
```

### Mecánica del escaneo SYN

```
  Escáner (192.168.1.10)              Objetivo (10.0.0.99)
         │                                   │
         │──── SYN ──► puerto 22 ───────────►│
         │◄─── SYN-ACK ────────────────────── │  → ABIERTO  ✔
         │──── RST ──►  (no completa handshake)│
         │                                   │
         │──── SYN ──► puerto 23 ───────────►│
         │◄─── RST+ACK ───────────────────── │  → CERRADO  ✗
         │                                   │
         │──── SYN ──► puerto 8888 ─────────►│
         │    (sin respuesta)                │  → FILTRADO ⚠
```

### Resultados del escaneo a `10.0.0.99`

```
╔══════════════════════════════════════════════════════╗
║         Nmap SYN Scan  →  10.0.0.99                 ║
╠══════════╦═══════════╦═══════════════╦══════════════╣
║  Puerto  ║  Estado   ║  Respuesta    ║  Servicio    ║
╠══════════╬═══════════╬═══════════════╬══════════════╣
║  22/tcp  ║  open  ✔  ║  SYN-ACK      ║  SSH         ║
║  80/tcp  ║  open  ✔  ║  SYN-ACK      ║  HTTP        ║
║ 443/tcp  ║  open  ✔  ║  SYN-ACK      ║  HTTPS       ║
║3306/tcp  ║  open  ✔  ║  SYN-ACK      ║  MySQL       ║
╠══════════╬═══════════╬═══════════════╬══════════════╣
║  23/tcp  ║  closed ✗ ║  RST+ACK      ║  Telnet      ║
║  25/tcp  ║  closed ✗ ║  RST+ACK      ║  SMTP        ║
║8080/tcp  ║  closed ✗ ║  RST+ACK      ║  HTTP-alt    ║
║4444/tcp  ║  closed ✗ ║  RST+ACK      ║  —           ║
╚══════════╩═══════════╩═══════════════╩══════════════╝
```

### Comando Nmap equivalente

```bash
nmap -sS -T4 10.0.0.99          # Escaneo SYN básico
nmap -sV -O  10.0.0.99          # + versión de servicio y OS
nmap -sV 10.0.0.99 -oA scan     # Guardar en .nmap / .xml / .gnmap
```

---

## Ejercicio 4 — Petición HTTP Completa

**Pasos en Wireshark:**

1. Filtro: `http`
2. Seleccionar paquete GET
3. Clic derecho → **Follow → TCP Stream**

### Flujo HTTP reconstruido

```
┌─────────────────────────────────────────────────────────────────────┐
│  ① PETICIÓN  192.168.1.10  →  93.184.216.34:80                     │
├─────────────────────────────────────────────────────────────────────┤
│  GET / HTTP/1.1                                                     │
│  Host: 93.184.216.34                                                │
│  User-Agent: Mozilla/5.0                                            │
│  Accept: text/html                                                  │
│  Connection: keep-alive                                             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ② RESPUESTA  93.184.216.34  →  192.168.1.10                       │
├─────────────────────────────────────────────────────────────────────┤
│  HTTP/1.1 200 OK                                                    │
│  Server: Apache/2.4.51                                              │
│  Content-Type: text/html; charset=UTF-8                             │
│  Content-Length: 1256                                               │
│                                                                     │
│  <html>...</html>                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Campos clave identificados

| Campo             | Petición          | Respuesta                    |
| ----------------- | ------------------ | ---------------------------- |
| Primera línea    | `GET / HTTP/1.1` | `HTTP/1.1 200 OK`          |
| Método           | `GET`            | —                           |
| URI               | `/`              | —                           |
| Código de estado | —                 | `200`                      |
| Mensaje de estado | —                 | `OK`                       |
| Servidor          | —                 | `Apache/2.4.51`            |
| Content-Type      | —                 | `text/html; charset=UTF-8` |
| Cifrado           | ❌ Texto plano     | ❌ Texto plano               |

---

## Análisis Hexadecimal

> **Principio:** Cada byte (0–255) se representa con exactamente **2 dígitos hex** (`00`–`FF`),
> lo que produce una representación compacta y de longitud fija.

### Conversiones de caracteres y valores de red

```
  Carácter  Decimal   Hex    Ejemplo
  ─────────────────────────────────────────
  'G'          71     47
  'E'          69     45     "GET " = 47 45 54 20
  'T'          84     54
  ' '          32     20
  ─────────────────────────────────────────
  Puerto   80         00 50  HTTP
  Puerto   443        01 BB  HTTPS
  Puerto   22         00 16  SSH
  Puerto   21         00 15  FTP
  Puerto   3306       0C EA  MySQL
  Puerto   53         00 35  DNS
  ─────────────────────────────────────────
  TTL      64         40     Linux / macOS
  TTL      128        80     Windows
  TTL      255        FF     Cisco IOS
  ─────────────────────────────────────────
  IP 192.168.1.10   →  C0 A8 01 0A
  IP 10.0.0.99      →  0A 00 00 63
  IP 93.184.216.34  →  5D B8 D8 22
```

### Mapa de la Cabecera IP (20 bytes mínimo)

```
  Byte:  00  01  02  03  04  05  06  07  08  09  10  11  12  13  14  15  16  17  18  19
         ┌───┬───┬───────┬───────┬───────┬───┬───┬───────┬───────────────┬───────────────┐
         │VHL│TOS│ Total │  ID   │ Flags │TTL│Pro│Checksum│  Source IP   │  Dest IP      │
         └───┴───┴───────┴───────┴───────┴───┴───┴───────┴───────────────┴───────────────┘

  Ejemplo real (paquete 192.168.1.10 → 93.184.216.34):
  45 00 00 28  12 34 00 00  40 06 XX XX  C0 A8 01 0A  5D B8 D8 22
  │  │  └──┘  └──┘  └──┘   │  │          └─────────┘  └─────────┘
  │  │  40B   ID    Flags   │  Proto=6       Src IP       Dst IP
  │  DSCP=0                 TTL=64(Linux)
  VHL=45 → IPv4, IHL=5×4=20B

  Campo           Bytes    Ejemplo           Descripción
  ────────────────────────────────────────────────────────────
  Versión + IHL   0        45                IPv4, header 20B
  DSCP/ECN        1        00                QoS = 0
  Total Length    2–3      00 28 = 40B       Tamaño total IP
  TTL             8        40 = 64           Time To Live
  Protocolo       9        06 = TCP          6=TCP 17=UDP 1=ICMP
  IP Origen       12–15    C0 A8 01 0A       192.168.1.10
  IP Destino      16–19    5D B8 D8 22       93.184.216.34
```

### Mapa de la Cabecera TCP (20 bytes mínimo)

```
  Byte:  00  01  02  03  04  05  06  07  08  09  10  11  12  13  14  15  16  17  18  19
         ┌───────┬───────┬───────────────┬───────────────┬───┬───┬───────┬───────┬───────┐
         │ Sport │ Dport │  Seq Number   │  Ack Number   │Off│Flg│  Win  │ Cksum │  Urg  │
         └───────┴───────┴───────────────┴───────────────┴───┴───┴───────┴───────┴───────┘

  Ejemplo (SYN desde puerto 54321 → 80):
  D4 31 00 50  00 00 03 E8  00 00 13 88  50 02 20 00  XX XX 00 00
  └─────┘└─────┘└─────────────┘└─────────────┘│  │   └─────┘
  54321   80    Seq=1000        Ack=5000      Offset  Win=8192
                                              50=5×4B  02=SYN

  Campo           Bytes    Ejemplo           Descripción
  ────────────────────────────────────────────────────────────
  Puerto origen   0–1      D4 31 = 54321     Puerto cliente
  Puerto destino  2–3      00 50 = 80        HTTP
  Seq Number      4–7      00 00 03 E8=1000  Número de secuencia
  Ack Number      8–11     00 00 13 88=5000  Número de ack
  Data Offset     12       5 → 5×4=20B       Tamaño cabecera TCP
  Flags           13       02 = SYN          Ver tabla siguiente
  Window          14–15    20 00 = 8192      Ventana de recepción
```

### Tabla de Flags TCP

```
  Flag      Bits      Hex    Binario    Filtro Wireshark        Uso
  ──────────────────────────────────────────────────────────────────────────
  SYN       000010    0x002  000000010  tcp.flags==0x002        Inicia conexión
  SYN+ACK   010010    0x012  000010010  tcp.flags==0x012        Servidor acepta
  ACK       010000    0x010  000010000  tcp.flags==0x010        Confirmación
  PSH+ACK   011000    0x018  000011000  tcp.flags==0x018        Datos inmediatos
  RST       000100    0x004  000000100  tcp.flags.reset==1      Resetea conexión
  RST+ACK   010100    0x014  000010100  tcp.flags==0x014        Puerto cerrado
  FIN       000001    0x001  000000001  tcp.flags.fin==1        Cierre ordenado
  FIN+ACK   010001    0x011  000010001  tcp.flags==0x011        Confirma cierre
```

### CyberChef — Operaciones útiles para análisis de red

```
  Operación          Uso
  ────────────────────────────────────────────────────────────
  From Hex           Bytes hex → texto ASCII legible
  From Base64        Decodificar credenciales HTTP Basic Auth
  URL Decode         Parámetros GET ofuscados
  XOR Brute Force    Detectar cifrado XOR simple en payloads
  Parse IP Range     Expandir CIDR a lista de IPs
  Entropy            Detectar datos cifrados/comprimidos
  MD5 / SHA256       Hash de payload para correlación forense

  Terminal equivalente de "From Hex":
    echo "47455420" | xxd -r -p          # Linux/macOS
    printf "\x47\x45\x54\x20"            # bash
    echo -n "GET /" | xxd -p             # texto → hex
```

---

## Cuestionario Q5–Q12

### Q5 — ¿Qué flag TCP indica el inicio de una nueva conexión?

**Respuesta: `SYN`**

```
  Cliente ──── SYN (0x002) ────────────► Servidor
  Cliente ◄─── SYN-ACK (0x012) ───────── Servidor
  Cliente ──── ACK (0x010) ────────────► Servidor
                    ✔ Conexión establecida
```

El bit SYN inicia el three-way handshake. Consume 1 número de secuencia aunque no lleve datos.

---

### Q6 — Al escanear con Nmap, un puerto que responde con RST+ACK está:

**Respuesta: `closed` (cerrado)**

```
  Estado      Respuesta del objetivo    Significado
  ──────────────────────────────────────────────────────────
  open        SYN-ACK (0x012)           Servicio activo escuchando
  closed      RST+ACK (0x014)           Accesible, sin servicio ligado
  filtered    Sin respuesta / ICMP      Firewall descarta los paquetes
  open|filt   Sin respuesta (UDP)       No se puede determinar
```

`RST` indica que el puerto **es accesible** (el host existe y responde) pero **ningún proceso** está escuchando en él.

---

### Q7 — ¿Por qué FTP se considera inseguro para producción?

**Respuesta: envía credenciales en texto plano sin cifrado alguno.**

```
  Captura de red (Wireshark) sobre FTP:
  ┌────────────────────────────────────────────────────────┐
  │ No. │ Info                                             │
  │ 12  │ Request: USER admin                              │  ← visible
  │ 13  │ Response: 331 Password required                  │
  │ 14  │ Request: PASS s3cr3tP@ssw0rd                     │  ← visible
  │ 15  │ Response: 230 Login successful.                  │
  └────────────────────────────────────────────────────────┘
  Cualquier nodo entre cliente y servidor puede leer esto.
```

---

### Q8 — ¿Qué protocolo usa ARP y en qué capa OSI opera?

**Respuesta: Capa 2 (Enlace de Datos), encapsulado en Ethernet.**

```
  Modelo OSI       Protocolo          EtherType
  ─────────────────────────────────────────────
  Capa 7 App       HTTP, FTP, DNS…
  Capa 4 Transp    TCP, UDP
  Capa 3 Red       IP
  Capa 2 Enlace    ARP  ◄────────     0x0806
  Capa 1 Física    Ethernet frames

  ARP Request:  "¿Quién tiene la IP 10.0.0.99? Respóndele a C0:A8:01:0A"
  ARP Reply:    "10.0.0.99 está en AA:BB:CC:DD:EE:FF"
```

ARP **no usa IP** — va directamente sobre Ethernet. Solo funciona dentro del mismo segmento LAN (mismo broadcast domain).

---

### Q9 — ¿Qué filtro Wireshark muestra solo los SYNs de un escaneo Nmap?

**Respuesta: `tcp.flags==0x002`**

```
  Filtro               Captura
  ─────────────────────────────────────────────────────────
  tcp.flags==0x002     Solo SYN puro    (inicio de conexión / escaneo)
  tcp.flags==0x012     Solo SYN-ACK     (puertos abiertos)
  tcp.flags==0x010     Solo ACK puro    (confirmaciones de datos)
  tcp.flags==0x014     Solo RST+ACK     (puertos cerrados)

  Para filtrar solo los SYNs del escáner:
    tcp.flags==0x002 && ip.src==192.168.1.10
```

`0x002` selecciona exactamente los paquetes con **solo el bit SYN activo** — los `SYN-ACK` (`0x012`) quedan excluidos.

---

### Q10 — ¿Qué indica un TTL de 128 en un paquete IP?

**Respuesta: el paquete fue generado probablemente por un sistema Windows.**

```
  Sistema Operativo    TTL inicial    Hex    Observado en captura
  ──────────────────────────────────────────────────────────────
  Windows              128            0x80   TTL=128 o menor
  Linux / macOS         64            0x40   TTL=64 o menor
  Cisco IOS / routers  255            0xFF   TTL=255 o menor

  El TTL se decrementa en 1 en cada salto de router.
  Si se recibe TTL=128 → el paquete no pasó por ningún router
                          y el host origen es Windows.
  Si se recibe TTL=127 → pasó por 1 router, origen Windows.
  Si se recibe TTL=63  → pasó por 1 router, origen Linux/macOS.
```

---

### Q11 — ¿Cuál es el puerto estándar DNS y qué protocolo de transporte usa?

**Respuesta: Puerto 53, principalmente UDP.**

```
  Situación                          Protocolo   Puerto
  ──────────────────────────────────────────────────────
  Consulta normal (≤ 512 bytes)      UDP         53
  Respuesta > 512 bytes              TCP         53
  Transferencia de zona (AXFR)       TCP         53
  DNS over TLS (DoT, cifrado)        TCP         853
  DNS over HTTPS (DoH)               TCP         443

  Filtro Wireshark:  dns   o   udp.port==53
```

---

### Q12 — ¿Qué operación CyberChef convierte bytes hex de Wireshark a texto?

**Respuesta: `From Hex`**

```
  CyberChef — operación "From Hex":
  ┌─────────────────────────────────────────────────────┐
  │  Input:   47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 │
  │  Output:  GET / HTTP/1.1                            │
  └─────────────────────────────────────────────────────┘

  Equivalente en terminal (Linux/macOS):
    echo "47455420" | xxd -r -p
    printf "\x47\x45\x54\x20"

  Equivalente en Python:
    bytes.fromhex("47455420").decode("ascii")   # → 'GET '

  Conversión inversa (texto → hex):
    echo -n "GET /" | xxd -p
    python3 -c "print('GET /'.encode().hex())"
```

---

## Referencia Rápida

### Filtros Wireshark

| Objetivo                                | Filtro                                       |
| --------------------------------------- | -------------------------------------------- |
| Solo ARP                                | `arp`                                      |
| Solo DNS                                | `dns`                                      |
| Solo HTTP                               | `http`                                     |
| Solo FTP                                | `ftp`                                      |
| Solo ICMP                               | `icmp`                                     |
| SYN puro (inicio/escaneo)               | `tcp.flags==0x002`                         |
| SYN-ACK (puertos abiertos)              | `tcp.flags==0x012`                         |
| RST (puertos cerrados)                  | `tcp.flags.reset==1`                       |
| Tráfico desde el cliente               | `ip.src==192.168.1.10`                     |
| Tráfico hacia el objetivo              | `ip.dst==10.0.0.99`                        |
| Tráfico web                            | `tcp.port==80 \|\| tcp.port==443`            |
| Buscar contraseña en cualquier paquete | `frame contains "PASS"`                    |
| SYNs del escáner                       | `tcp.flags==0x002 && ip.src==192.168.1.10` |
| Puertos abiertos detectados             | `tcp.flags==0x012 && ip.src==10.0.0.99`    |
| Puertos filtrados                       | `tcp.analysis.retransmission`              |

### Comandos tshark

```bash
# Listar paquetes
tshark -r lab_traffic.pcap

# Jerarquía de protocolos
tshark -r lab_traffic.pcap -q -z io,phs

# IPs y puertos destino de todos los SYN
tshark -r lab_traffic.pcap -Y tcp.flags.syn==1 \
       -T fields -e ip.dst -e tcp.dstport

# Credenciales FTP expuestas
tshark -r lab_traffic.pcap -Y ftp \
       -T fields -e ftp.request.command -e ftp.request.arg

# Estadísticas de conversaciones TCP
tshark -r lab_traffic.pcap -q -z conv,tcp

# URIs HTTP
tshark -r lab_traffic.pcap -Y http.request \
       -T fields -e http.request.full_uri
```

### Comandos Nmap

```bash
nmap -sS -T4 10.0.0.99                    # SYN scan (requiere root)
nmap -sV -O  10.0.0.99                    # Versión de servicios + OS
nmap --script vuln 10.0.0.99              # Scripts de vulnerabilidades
nmap -sV 10.0.0.99 -oA resultados_scan   # Guardar en .nmap/.xml/.gnmap

# Capturar tráfico durante el escaneo
tcpdump -i eth0 -w scan_nmap.pcap &
nmap -sS 10.0.0.99
wireshark scan_nmap.pcap
```

---

## Resumen

| Ejercicio           | Herramienta usada           | Resultado clave                |
| ------------------- | --------------------------- | ------------------------------ |
| 1. Credenciales FTP | Filtro `ftp`              | `admin` / `s3cr3tP@ssw0rd` |
| 2. TCP Handshake    | Filtro `tcp.flags.syn==1` | SYN → SYN-ACK → ACK          |
| 3. Escaneo Nmap     | Filtros SYN / SYN-ACK / RST | Abiertos: 22, 80, 443, 3306    |
| 4. HTTP completo    | Follow TCP Stream           | `GET /` → `200 OK`        |

> **Conclusión de seguridad:** Los protocolos sin cifrado (FTP, HTTP, Telnet) exponen credenciales
> y datos en texto plano capturables con cualquier sniffer.
> La solución es migrar a **SFTP**, **HTTPS** y **SSH** respectivamente.
