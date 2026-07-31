# PrinterManager

Sistema interno para registrar impresoras y detectar posibles impresoras en una red autorizada.

## Ejecutar

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

Luego abre:

```text
http://127.0.0.1:8000
```

## Escanear impresoras

En el panel escribe un rango CIDR de tu red, por ejemplo:

```text
192.168.1.0/24
10.0.0.0/24
172.16.1.0/24
```

La deteccion revisa puertos comunes de impresoras: `80`, `443`, `515`, `631` y `9100`.

Usa esta herramienta solo en redes donde tengas autorizacion administrativa.
