# EVA ICS WebEngine

Web engine for [EVA ICS](https://www.bohemia-automation.com/software/eva4/) -
open source platform for industrial and home IoT which allows to create modern
web-HMI applications for EVA ICS.

Technical documentation: <https://info.bma.ai/en/actual/eva-webengine/index.html>

## Migration to 0.9

* The engine fields `password`, `api_token` and `apikey` are now private, which
  allows to register global variables with less security risks.

* To set authentication credentials, use the corresponding methods of the
  engine object: `set_login_password`, `set_api_key`.
