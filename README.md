# AutoSSLToUCE
Demo project to show how to make an SSL connection to a Crestron UC-Engine and send a single command without user interaction.

#### Important!
In order to pass the sslpolicy of you need to install the [UC-Engine certificate](cert/srv_cert.crt) file on your client.<br />
Choose "Local Machine" as the Store Location.<br />
Choose "Thrusted Root Certification Authorities" as the Certificate store.

## Use:
`AutoSSLToUCE <IP or hostname> <username> <password> <command>`

## Example:
`AutoSSLToUCE "10.80.23.50" admin sfb "ver -v"`
