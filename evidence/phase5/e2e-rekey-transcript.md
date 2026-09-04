# Phase 5 — Forward secrecy: rekeying across a live session (transcript)

The end-to-end key is renegotiated roughly every 20 s (set via `--rekey 20`; default 60 s). Each `E2E rekey -> epoch N` line shows a fresh fingerprint that both clients agree on. Messages sent before, across, and after each rotation are all delivered and decrypted; the server's RELAY log stays opaque throughout (truncated here).

Interleaved from the per-party logs, ordered by timestamp (UTC).

```
07:22:36  SERVER    | START phase3 DH + AES-256-GCM relay, authenticated (PKI) on 0.0.0.0:5555 (log: rekey-server.log)
07:22:38  alice(C1) | server certificate verified (chatserver.local); key exchange complete, fingerprint 8607740babb827bb
07:22:38  alice(C1) | connected to 10.10.0.10:5555 as alice
07:22:38  bob(C2)   | server certificate verified (chatserver.local); key exchange complete, fingerprint 46209c8ebff33a56
07:22:38  bob(C2)   | connected to 10.10.0.10:5555 as bob
07:22:38  bob(C2)   | * alice joined
07:22:38  SERVER    | CONN  10.10.0.12:50422
07:22:38  SERVER    | CONN  10.10.0.11:56338
07:22:38  SERVER    | KEX   10.10.0.12:50422 session established, fingerprint=46209c8ebff33a56
07:22:38  SERVER    | KEX   10.10.0.11:56338 session established, fingerprint=8607740babb827bb
07:22:38  SERVER    | LOGIN bob from 10.10.0.12:50422
07:22:38  SERVER    | LOGIN alice from 10.10.0.11:56338
07:22:40  alice(C1) | * requesting end-to-end session with bob ...
07:22:40  alice(C1) | * end-to-end session established with bob, fingerprint edadeade4196261a
07:22:40  bob(C2)   | * end-to-end session established with alice, fingerprint edadeade4196261a
07:22:40  SERVER    | RELAY alice -> bob : "__E2E_INIT__BQAAAAABAC8/xMI+kZmwXM9kxemR/1zNUzJicZkQoxQD7MdfTJIt1HylGxOMGIYAXb4tcONHoXuHxIlRrAWEtLnLSdIg0xdQ49GVchUke80HDEBahRRaIkOG8rmT4MQRZwjI+RZA4scYgOIop6kwO31mOwV5d4ifajl7h4h/EGsIbHkeG80NUVWvi9NQ1dElp20Hf1N14fdEdI7mGFo51GCfKapN3/3hqX5r2mVgbBoPRVLImf8QSNWiEikZ39DSI4IMX4n3vsE+ugjqooyF+jRYD9hwqHBzYGIPl30FjCQPt3U1lIpIT/BrmknavnXfKgS3dsTeTjS/Gds4Ct37Aq5G4JdPzso="
07:22:40  SERVER    | RELAY bob -> alice : "__E2E_ACK__BQAAAAABAF33tK6pds9jeTw4HaukAsMQqnsyQbMpBuaC4FGNg+aQ9IR3eqU1Z0PsMKYGiRHFqZzOu1bUmaBjM5ovkcqUFuQo45E0mB0RZDkybTP76CbpMkwlIthbvMm+SLRmSaT3y4YldPqGCtUaJlGmsTWLiVyrfKzcCcR/YbXo+zDJkAzaVgIPPJojdtzJ9YQbjFFw/msDW5wjD9E+vHf/OpTFDCvqn4eba+Pn3gvpRHH/fJ+L0gYmykJIKNBROCRcbfBcQ6j87bdDs1Vwspwv/ivmVogS69vzjNq9XcYvNmq8WgakPd+w8xHF4feS10mm2Wtw0goqyiKnE4c6Ka7ETwZmUEU="
07:22:43  alice(C1) | you -> bob [e2e]: epoch 0: forward secrecy demo
07:22:43  bob(C2)   | alice [e2e]> epoch 0: forward secrecy demo
07:22:43  SERVER    | RELAY alice -> bob : "__E2E_MSG__AAAAAPaelFAxpCILNjvXomJeA5fR/f6JEbkR5+Ty+dsmhmd..."
07:23:01  alice(C1) | E2E rekey -> epoch 1 with bob  fingerprint d5b9d6fbd2bad80f
07:23:01  alice(C1) | you -> bob [e2e]: after the first rotation
07:23:01  bob(C2)   | E2E rekey -> epoch 1 with alice  fingerprint d5b9d6fbd2bad80f
07:23:01  bob(C2)   | alice [e2e]> after the first rotation
07:23:01  SERVER    | RELAY alice -> bob : "__E2E_INIT__BQAAAAEBAO+xFLuuq7QniOhQk8mZAahksHSH6FB/MS1vwTHbzJk1f9NdJT+kgG6MtohzPdHhUL9AUWfuQLEBGczhQeFnh+rUjKdExJmkOmQGrw/OEg13kCUCN04daly13S3wh/fBpVFcvF4iqKYbCTXZZFoYEIu1KpgEihwhC720yvzPZ0wbYz6SSqNmZPuXTEL43MKYeq1rlGojs0rs9iXhpQ0+ycEwfQdt4dMBH4GIxe53+MpfpPfj50kamwiUku8lSdZXhn0BHAJTgHLvwCTmMCWXyytIbVTbTNOZw6j/AE5U948i3Nc0dJCyd1QdzS4+nslb7G/cdSmpIuQ3nYDuld+RfYg="
07:23:01  SERVER    | RELAY bob -> alice : "__E2E_ACK__BQAAAAEBABOiAXFZ+OnWIuYG9khpP9GVLMxEa6idckrB/eufpP0nJgBjYFmOZ5nOteuMg81AtLjvRSvtcfMTAbdDQ4KTNW/49caNGMMvJ3DnyVlMrT5SzE/LI2a4ikBhnWJnM3wTVyhA8NUkxmiv1hRzAvtfKhNk0wtNYysJxvnDcxunOjDECtql8am0lX6jB/Ovo5pLtBuyU16sk4b/YVA/baTNEf6ym/etcz0CsCPhiq2jes9+Zirf78ReKi3y+f2//gUb7IpzhSJ/vqxcx+EekBwwiA/6vMdaT+GF90kGdzwMaQbBVGv8dZDVZchzsEY88QNZXbxLfPhwn9WHH8bSXCNqKiA="
07:23:01  SERVER    | RELAY alice -> bob : "__E2E_MSG__AAAAAQ4hkzifOSct1/HwxzgJPGoA7dcJFz8eAH2X04dtSQN..."
07:23:03  alice(C1) | bob [e2e]> replying across a rekey
07:23:03  bob(C2)   | you -> alice [e2e]: replying across a rekey
07:23:03  SERVER    | RELAY bob -> alice : "__E2E_MSG__AAAAAUwI13I9/jbl+vSiiae6XTrswM6hdnSzlvtDvTEpglR..."
07:23:21  alice(C1) | E2E rekey -> epoch 2 with bob  fingerprint 0ab850ced4712d7f
07:23:21  alice(C1) | you -> bob [e2e]: after the second rotation
07:23:21  bob(C2)   | E2E rekey -> epoch 2 with alice  fingerprint 0ab850ced4712d7f
07:23:21  bob(C2)   | alice [e2e]> after the second rotation
07:23:21  SERVER    | RELAY alice -> bob : "__E2E_INIT__BQAAAAIBAHK/jYBgdxP0aioIzTbXt73N0bbJm+eGxlpl+4yRDv+t91tYYhQXU/dr3KdT7MVdAiraqZDPG6NB2hD3+qRcMxVRKITpucDwyix1xlfUbQWrCkba0bb2+60D7b2+b96WxdIVzz0t4Fam+mnUSB3eJhWvHzlFT89Fj6nioFOTojd7XMWO9t/oDh0nHBK/wso9bvilxQe9pLG5QBZXrqM+AbaNtLzuo4qTYV7jpxyRtOaNIT6qP8pQh8V7WrS+HRJMmYT7pI6erofZ5v0OWG8tI9DhpoHOvBH5GsMBQtdie9g8DU6C0gaGY584z6V5Ki5YjoRWh7Qc5QqXAVnxgKsGi5g="
07:23:21  SERVER    | RELAY bob -> alice : "__E2E_ACK__BQAAAAIBAJIrpfRICDs+GP1JtVtPwk1yAmWwlxGz/DW2L1Qh6+6yqNYP3oerg+M3jeQJXJ77iYy+i0N3NjqCIQmhTXJ0m2FBrBiXw3Wch0RiJ4TEeCjn06Esbofbq24AtFsHYnRHSflzvGI0Iq869LngYXZV+ELQJbtu1BDDYrf7igVhEW3S5PsQmG8VCxmkV4iFO2LJJCvO4qzoP9yXtJfzfSv4SCFYLuFgxDEvfxLda9YSuQYa7lGu151dMxn1DNOXRwwquMJElAHVvDuxHInsdxvxRGSKA2oqeg8tvNRYzgxor1IN+ckn8ju20KErhHZ1ac4JzquOAcycptnDjsH69J4dih4="
07:23:21  SERVER    | RELAY alice -> bob : "__E2E_MSG__AAAAAmCDB4PVKqIYK4VTEg+z7n3V7ToNAoIoqLw7pV0NdVO..."
07:23:24  alice(C1) | * bye
07:23:24  bob(C2)   | * alice left
07:23:24  SERVER    | QUIT  alice
07:23:24  SERVER    | CLOSE alice (quit)
07:23:43  bob(C2)   | * bye
07:23:43  SERVER    | QUIT  bob
07:23:43  SERVER    | CLOSE bob (quit)
07:23:51  SERVER    | STOP  shutting down
```
