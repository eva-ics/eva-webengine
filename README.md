# EVA ICS WebEngine

Web engine for [EVA ICS](https://www.bohemia-automation.com/software/eva4/) -
open source platform for industrial and home IoT which allows to create modern
web-HMI applications for EVA ICS.

Web engine works perfectly both with vanilla JavaScript as well as with
high-level frameworks, such as React and Vue.

Note: EVA ICS Web Engine is currently in alpha stage. Use in production only if
you know what you are doing.

## A quick example for vanilla JS

```shell
npm install --save @eva-ics/webengine
```

```typescript
import { Eva, EventKind } from "@eva-ics/webengine";

const eva = new Eva();

// optionally register window.$eva for older HMI apps and for testing purposes
eva.register_legacy_globals();

const log = eva.log; // Get the engine console logger

eva.apikey = "secret";
// required for development servers only, remove when hosted in EVA ICS HMI
eva.api_uri = "http://localhost:7727";

eva.watch("sensor:tests/temperature", (state) => {
  document.getElementById("temperature")!.innerHTML = state.value;
  });

eva.on(EventKind.LoginSuccess, () => {
  log.info("logged into", eva.system_name());
});

eva.on(EventKind.LoginFailed, (err: EvaError) => {
  log.error("login failed", err);
});

eva.start();
```

## Migration from EVA ICS JS Framework

EVA ICS WebEngine is fully compatible with EVA ICS JS Framework except the
following:

* WebEngine is distributed as a TypeScript ES module only

* EVA ICS v3 is no longer supported

* The primary class has been renamed from "EVA" to "Eva"

* the default "Eva"-class object can be registered in web browsers with
manually calling "register\_legacy\_globals()" method of the main class.

* Web socket mode is now turned on by default

* Eva.interval() has been renamed to Eva.set\_interval()

* Eva.log\_level() has been renamed to Eva.set\_log\_level()

* Eva.debug turns debug logs however to see messages in the JS console, its
log level must be additionally set to "Verbose". Despite of that, it is not
recommended to enable debug mode in production as it causes CPU load.

* "fetch" is no longer bundled as it is present in the majority of
environments. For older environments consider manually importing a polyfill
(e.g. "node-fetch") and setting it to EvaOBJECT.external.fetch

* "WebSocket" is no longer bundled by default. If working in environment with
no native websocket support, consider either setting "EvaOBJECT.ws\_mode" to
false or using an external module (e.g. "ws") and setting it to
EvaOBJECT.external.WebSocket

* QRious is no longer bundled by default. If QR codes are required, consider
manually importing "QRious" module and setting it to EvaOBJECT.external.QRious
(for web apps is enough to load QRious before the framework)

* EVA ICS HMI WASM extension is already compatible with the new module,
consider asking your support engineer for upgrade.
