const eva_webengine_version = "0.6.5";

import { Logger } from "bmat/log";
import { cookies } from "bmat/dom";

enum EvaErrorKind {
  NOT_FOUND = -32001,
  ACCESS_DENIED = -32002,
  SYSTEM_ERROR = -32003,
  OTHER = -32004,
  NOT_READY = -32005,
  UNSUPPORTED = -32006,
  CORE_ERROR = -32007,
  TIMEOUT = -32008,
  INVALID_DATA = -32009,
  FUNC_FAILED = -32010,
  ABORTED = -32011,
  ALREADY_EXISTS = -32012,
  BUSY = -32013,
  METHOD_NOT_IMPLEMENTED = -32014,
  TOKEN_RESTRICTED = -32015,
  IO = -32016,
  REGISTRY = -32017,
  EVAHI_AUTH_REQUIRED = -32018,

  ACCESS_DENIED_MORE_DATA_REQUIRED = -32022,

  PARSE = -32700,
  INVALID_REQUEST = -32600,
  METHOD_NOT_FOUND = -32601,
  INVALID_PARAMS = -32602,
  INTERNAL_RPC = -32603,

  BUS_CLIENT_NOT_REGISTERED = -32113,
  BUS_DATA = -32114,
  BUS_IO = -32115,
  BUS_OTHER = -32116,
  BUS_NOT_SUPPORTED = -32117,
  BUS_BUSY = -32118,
  BUS_NOT_DELIVERED = -32119,
  BUS_TIMEOUT = -32120,
  BUS_ACCESS = -32121
}

enum EventKind {
  HeartBeatSuccess = "heartbeat.success",
  HeartBeatError = "heartbeat.error",
  LoginSuccess = "login.success",
  LoginFailed = "login.failed",
  LoginOTPRequired = "login.otp_required",
  LoginOTPInvalid = "login.otp_invalid",
  LoginOTPSetup = "login.otp_setup",
  WsEvent = "ws.event",
  ServerReload = "server.reload",
  ServerRestart = "server.restart",
  LogRecord = "log.record",
  LogPostProcess = "log.postprocess"
}

enum StateProp {
  Status = "status",
  Value = "value",
  Any = "any"
}

const GLOBAL_BLOCK_NAME = ".";

interface EvaConfig {
  engine?: EvaEngineConfig;
}

interface EvaEngineConfig {
  api_uri?: string;
  apikey?: string;
  debug?: boolean | number;
  login?: string;
  password?: string;
  set_auth_cookies?: boolean;
  state_updates?: boolean | Array<string>;
  wasm?: boolean | string;
  ws_mode?: boolean;
  log_params?: LogParams;
  interval: { [key in IntervalKind]: number };
}

interface OTPParams {
  size?: number;
  issuer?: string;
  user?: string;
  xtr?: string;
}

interface HiQRParams {
  size?: number;
  url?: string;
  user?: string;
  password?: string;
}

interface LogRecord {
  dt: string;
  h: string;
  l: number;
  lvl: string;
  mod: string;
  msg: string;
  t: number;
  th: string | null;
}

interface WsCommand {
  m: string;
  p?: any;
}

interface LoginPayload {
  k?: string;
  u?: string;
  p?: string;
  a?: string;
  xopts?: object;
}

interface SvcMessage {
  kind: string;
  svc: string;
  message?: string;
  value?: string;
}

interface JsonRpcRequest {
  jsonrpc: string;
  method: string;
  params?: object;
  id: number;
}

interface JsonRpcResponse {
  jsonrpc: string;
  result?: object;
  error?: EvaError;
  id: number;
}

interface External {
  fetch?: any;
  WebSocket?: any;
  QRious?: any;
}

interface ActionResult {
  elapsed: number;
  exitcode: number | null;
  finished: boolean;
  node: string;
  oid: string;
  params: any;
  priority: number;
  status: string;
  svc: string;
  time: any;
  uuid: string;
  out: null | string;
  err: null | string;
}

interface StatePayload {
  full?: boolean;
  i?: string | Array<string>;
}

interface LvarIncrDecrResult {
  result: number;
}

interface LogParams {
  level: number;
  records: number;
}

interface ItemState {
  act?: number;
  connected?: boolean;
  enabled?: boolean;
  ieid?: Array<number>;
  meta?: object;
  node?: string;
  oid?: string;
  status?: number | null;
  t?: number;
  value: any;
}

enum IntervalKind {
  AjaxReload = "ajax_reload",
  AjaxLogReload = "log_reload",
  ActionWatch = "action_watch",
  Heartbeat = "heartbeat",
  Reload = "reload",
  Restart = "restart",
  WSBufTTL = "ws_buf_ttl"
}

class EvaError {
  code: number;
  message?: string;
  data?: any;
  constructor(code: number, message?: string, data?: any) {
    this.code = code;
    this.message = message;
    this.data = data;
  }
}

class EvaBulkRequestPartHandler {
  fn_ok?: (result: any) => void;
  fn_err?: (result: any) => void;

  constructor() {}
  then(fn_ok: (result: any) => void) {
    this.fn_ok = fn_ok;
    return this;
  }
  catch(fn_err: (err: any) => void) {
    this.fn_err = fn_err;
    return this;
  }
}

class EvaBulkRequest {
  requests: Map<number, EvaBulkRequestPartHandler>;
  payload: Array<any>;
  eva: Eva;

  constructor(eva: Eva) {
    this.requests = new Map<number, EvaBulkRequestPartHandler>();
    this.payload = [];
    this.eva = eva;
  }
  /**
   * Prepare API function call for bulk calling
   *
   * Calls any available SFA API function
   *
   * @param p1 item OID (if required) or API call params
   * @param p2 extra call params or empty object
   * @param fn_ok function which is executed on successfull call
   * @parma fn_err function which is executed on error
   *
   * @returns Part handler object
   */
  prepare(
    method: string,
    p1: string | object,
    p2?: object
  ): EvaBulkRequestPartHandler {
    let params: any;
    if (typeof p1 === "string" || Array.isArray(p1)) {
      params = p2 || {};
      params.i = p1;
    } else {
      params = p1;
    }
    let p = this.eva._prepare_call_params(params);
    let payload: JsonRpcRequest = this.eva._prepare_api_call(method, p);
    let req = new EvaBulkRequestPartHandler();
    this.requests.set(payload.id, req);
    this.payload.push(payload);
    return req;
  }
  /**
   * Perform bulk API call
   */
  call(): Promise<boolean> {
    let api_uri = `${this.eva.api_uri}/jrpc`;
    this.eva._debug("call_bulk", `${api_uri}`);
    return new Promise((resolve, reject) => {
      this.eva.external
        .fetch(api_uri, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          redirect: "error",
          body: JSON.stringify(this.payload)
        })
        .then((response: any) => {
          if (response.ok) {
            response
              .json()
              .then((data: JsonRpcResponse) => {
                this.eva._debug("call_bulk success");
                if (Array.isArray(data)) {
                  data.forEach((d) => {
                    if (
                      typeof d.id === "undefined" ||
                      (typeof d.result === "undefined" &&
                        typeof d.error === "undefined")
                    ) {
                      reject({
                        code: -32009,
                        message: "Invalid server response",
                        data: d
                      });
                    } else {
                      let id = d.id;
                      let req = this.requests.get(id);
                      let fn_ok;
                      let fn_err;
                      if (req !== undefined) {
                        fn_ok = req.fn_ok;
                        fn_err = req.fn_err;
                      }
                      if (d.error !== undefined) {
                        this.eva._debug(
                          "call_bulk req",
                          `${id} failed: ${d.error.code} (${d.error.message})`
                        );
                        if (fn_err) {
                          fn_err({
                            code: d.error.code,
                            message: d.error.message,
                            data: d
                          });
                        }
                      } else {
                        if (this.eva.debug == 2) {
                          this.eva.log.info(
                            `call_bulk API ${id} ${(req as any).func} response`,
                            d.result
                          );
                        }
                        if (fn_ok) {
                          fn_ok(d.result);
                        }
                      }
                    }
                  });
                  resolve(true);
                } else {
                  let code = EvaErrorKind.INVALID_DATA;
                  let message = "Invalid server response (not an array)";
                  this.eva._debug("call_bulk", `failed: ${code} (${message})`);
                  reject(new EvaError(code, message, data));
                }
              })
              .catch((err: any) => {
                let code = EvaErrorKind.INVALID_DATA;
                let message = "Invalid server response";
                this.eva._debug("call_bulk", `failed: ${code} (${message})`);
                reject(new EvaError(code, message, err));
              });
          } else {
            let code = EvaErrorKind.CORE_ERROR;
            let message = "Server error";
            this.eva._debug("call_bulk", `failed: ${code} (${message})`);
            reject(new EvaError(code, message));
          }
        })
        .catch((err: any) => {
          let code = EvaErrorKind.CORE_ERROR;
          let message = "Server error";
          this.eva._debug("call_bulk", `failed: ${code} (${message})`);
          reject(new EvaError(code, message, err));
        });
    });
  }
}

class Eva_ACTION {
  eva: Eva;

  constructor(eva: Eva) {
    this.eva = eva;
  }
  /**
   * Call unit action with value=1
   *
   * @param oid {string} unit OID
   * @param wait {boolean} wait until the action is completed (default: true)
   */
  async start(oid: string, wait = true): Promise<ActionResult> {
    return this.exec(oid, { v: 1 }, wait);
  }
  /**
   * Call unit action with value=0
   *
   * @param oid {string} unit OID
   * @param wait {boolean} wait until the action is completed (default: true)
   */
  async stop(oid: string, wait = true): Promise<ActionResult> {
    return this.exec(oid, { v: 0 }, wait);
  }
  /**
   * Call unit action to toggle its value
   *
   * @param oid {string} unit OID
   * @param wait {boolean} wait until the action is completed (default: true)
   */
  async toggle(oid: string, wait = true): Promise<ActionResult> {
    return this._act("action.toggle", oid, {}, wait);
  }
  /**
   * Call unit action
   *
   * @param oid {string} unit OID
   * @param params {object} action params
   * @param wait {boolean} wait until the action is completed (default: true)
   */
  exec(oid: string, params: object, wait = true) {
    return this._act("action", oid, params, wait);
  }
  /**
   * Terminate all unit actions
   *
   * @param oid {string} unit OID
   */
  async kill(oid: string) {
    await this.eva.call("action.kill", oid);
  }
  /**
   * Terminate a unit action
   *
   * @param uuid {string} action uuid
   */
  async terminate(uuid: string) {
    let method = "action.terminate";
    await this.eva.call(method, { u: uuid });
  }
  /**
   * Run lmacro
   *
   * @param oid {string} lmacro oid
   * @param params {object} call params
   * @param wait {boolean} wait until completed (default: true)
   */
  async run(oid: string, params?: object, wait = true): Promise<ActionResult> {
    return this._act("run", oid, params, wait);
  }
  _act(
    method: string,
    oid: string,
    params?: object,
    wait = false
  ): Promise<ActionResult> {
    return new Promise((resolve, reject) => {
      this.eva
        .call(method, oid, params)
        .then((data: ActionResult) => {
          if (wait === false) {
            resolve(data);
          } else {
            this.eva.watch_action(data.uuid, (res: ActionResult | EvaError) => {
              if ((res as ActionResult).uuid !== undefined) {
                if ((res as ActionResult).finished) {
                  resolve(res as ActionResult);
                }
              } else {
                reject(res);
              }
            });
          }
        })
        .catch((err) => {
          reject(err);
        });
    });
  }
}

class Eva_LVAR {
  eva: Eva;

  constructor(eva: Eva) {
    this.eva = eva;
  }
  /**
   * Reset lvar (set status to 1)
   *
   * @param oid {string} lvar oid
   */
  async reset(oid: string) {
    await this.eva.call("lvar.reset", oid);
  }
  /**
   * Clear lvar (set status to 0)
   *
   * @param oid {string} lvar oid
   */
  async clear(oid: string) {
    await this.eva.call("lvar.clear", oid);
  }
  /**
   * Toggle lvar status
   *
   * @param oid {string} lvar oid
   */
  async toggle(oid: string) {
    await this.eva.call("lvar.toggle", oid);
  }
  /**
   * Increment lvar value
   *
   * @param oid {string} lvar oid
   *
   * @returns the new value
   */
  async incr(oid: string): Promise<number> {
    let data = (await this.eva.call("lvar.incr", oid)) as LvarIncrDecrResult;
    return data.result;
  }
  /**
   * Decrement lvar value
   *
   * @param oid {string} lvar oid
   *
   * @returns the new value
   */
  async decr(oid: string) {
    let data = (await this.eva.call("lvar.decr", oid)) as LvarIncrDecrResult;
    return data.result;
  }
  /**
   * Set lvar state
   *
   * @param oid {string} lvar oid
   * @param status {numberr} lvar status
   * @param value lvar value
   */
  async set(oid: string, status?: number, value?: any) {
    let params: any = {};
    if (status !== undefined) {
      params.status = status;
    }
    if (value !== undefined) {
      params.value = value;
    }
    if (Object.keys(params).length) {
      await this.eva.call("lvar.set", oid, params);
    }
  }
  /**
   * Set lvar status
   *
   * @param oid {string} lvar oid
   * @param status {number} lvar status
   */
  async set_status(oid: string, status: number) {
    await this.set(oid, status);
  }
  /**
   * Set lvar value
   *
   * @param oid {string} lvar oid
   * @param value lvar value
   */
  async set_value(oid: string, value: any) {
    await this.set(oid, (value = value));
  }

  /**
   * Get lvar expiration time left
   *
   * @param lvar_oid {string} lvar OID
   *
   * @returns seconds to expiration, -1 if expired, -2 if stopped
   */
  expires(lvar_oid: string): number | null | undefined {
    // get item state
    let state = this.eva.state(lvar_oid) as ItemState;
    // if no such item
    if (state === undefined || state.t === undefined) return undefined;
    // if item has no expiration or expiration is set to zero
    if (
      !state.meta ||
      (state.meta as any).expires === undefined ||
      (state.meta as any).expires == 0
    ) {
      return null;
    }
    // if timer is disabled (stopped), return -2
    if (state.status == 0) return -2;
    // if timer is expired, return -1
    if (state.status == -1) return -1;
    let t =
      (state.meta as any).expires -
      new Date().getTime() / 1000 +
      this.eva.tsdiff +
      state.t;
    if (t < 0) t = 0;
    return t;
  }
}

class _EvaStateBlock {
  state_updates: boolean | Array<string>;
  eva: Eva;
  name: string;
  _ajax_reloader: any;
  constructor(
    name: string,
    state_updates: boolean | Array<string>,
    engine: Eva
  ) {
    this.name = name;
    this.state_updates = state_updates;
    this.eva = engine;
  }
  _start() {
    if (this.eva.ws_mode) {
      this.eva._start_ws(this.state_updates, this.name);
    }
    this.eva._load_states(this.state_updates, this.name).then(() => {
      if (this.eva.ws_mode) {
        const reload = this.eva._intervals.get(IntervalKind.Reload) as number;
        if (reload) {
          this._ajax_reloader = setInterval(() => {
            this.eva._load_states(this.state_updates, this.name);
          }, reload * 1000);
        }
      } else {
        this._ajax_reloader = setInterval(() => {
          this.eva._load_states(this.state_updates, this.name);
        }, this.eva._intervals.get(IntervalKind.AjaxReload) as number);
      }
    });
  }
  _restart() {
    this._stop();
    this._start();
  }
  _stop() {
    if (this._ajax_reloader) {
      clearInterval(this._ajax_reloader);
    }
    const ws = this.eva.ws.get(this.name);
    if (ws) {
      this.eva.ws.delete(this.name);
      try {
        ws.onclose = null;
        ws.onerror = function () {};
        ws.close();
      } catch (err) {
        // web socket may be still open, will close later
        setTimeout(() => {
          try {
            ws.close();
          } catch (err) {}
        }, 100);
      }
    }
  }
}

class Eva {
  action: Eva_ACTION;
  lvar: Eva_LVAR;
  api_uri: string;
  apikey: string;
  api_token: string;
  //api_version: number | null;
  authorized_user: string | null;
  clear_unavailable: boolean;
  debug: boolean | number;
  external: External;
  evajw: any;
  in_evaHI: boolean;
  log_params: LogParams;
  log: Logger;
  logged_in: boolean;
  login: string;
  login_xopts: object | null;
  log_level_names: Map<number, string>;
  password: string;
  set_auth_cookies: boolean;
  state_updates: boolean | Array<string>;
  tsdiff: number;
  version: string;
  wasm: boolean | string;
  ws_mode: boolean;
  server_info: any;
  _api_call_id: number;
  _handlers: Map<EventKind, (...args: any[]) => void | boolean>;
  _intervals: Map<IntervalKind, number>;
  _ws_handler_registered: boolean;
  _heartbeat_reloader: any;
  _ajax_reloader: any;
  _log_reloader: any;
  _scheduled_restarter: any;
  _states: Map<string, Map<string, ItemState>>;
  _blocks: Map<string, _EvaStateBlock>;
  _last_ping: Map<string, number | null>;
  _last_pong: Map<string, number | null>;
  ws: Map<string, WebSocket>;
  _action_states: Map<string, ActionResult>;
  _action_watch_functions: Map<
    String,
    Array<(result: ActionResult | EvaError) => void>
  >;
  _log_subscribed: boolean;
  _log_started: boolean;
  _log_first_load: boolean;
  _log_loaded: boolean;
  _update_state_functions: Map<string, Array<(state: ItemState) => void>>;
  _update_state_mask_functions: Map<string, Array<(state: ItemState) => void>>;
  _lr2p: Array<LogRecord>;

  constructor() {
    this.version = eva_webengine_version;
    this.log = new Logger();
    this.login = "";
    this.password = "";
    this.login_xopts = null;
    this.apikey = "";
    this.api_uri = "";
    this.set_auth_cookies = true;
    this.api_token = "";
    this.authorized_user = null;
    this.logged_in = false;
    this.debug = false;
    this.state_updates = true;
    this.wasm = false;
    this.clear_unavailable = false;
    this._ws_handler_registered = false;
    this.ws_mode = true;
    this.ws = new Map();
    //this.api_version = null;
    this._api_call_id = 0;
    this.tsdiff = 0;
    this._last_ping = new Map();
    this._last_ping.set(GLOBAL_BLOCK_NAME, null);
    this._last_pong = new Map();
    this._last_pong.set(GLOBAL_BLOCK_NAME, null);
    this._log_subscribed = false;
    this._log_started = false;
    this._log_first_load = false;
    this._log_loaded = false;
    this._lr2p = [];
    this.in_evaHI =
      typeof navigator !== "undefined" &&
      typeof navigator.userAgent === "string" &&
      navigator.userAgent.startsWith("evaHI ");
    this.log_params = {
      level: 20,
      records: 200
    };
    this._update_state_functions = new Map();
    this._update_state_mask_functions = new Map();
    this._handlers = new Map([[EventKind.HeartBeatError, this.restart]]);
    this._handlers.set(EventKind.HeartBeatError, this.restart);
    this._states = new Map();
    this._states.set(GLOBAL_BLOCK_NAME, new Map());
    this._blocks = new Map();
    this._intervals = new Map([
      [IntervalKind.AjaxReload, 2],
      [IntervalKind.AjaxLogReload, 2],
      [IntervalKind.ActionWatch, 0.5],
      [IntervalKind.Heartbeat, 5],
      [IntervalKind.Reload, 5],
      [IntervalKind.Restart, 1],
      [IntervalKind.WSBufTTL, 0]
    ]);
    this.log_level_names = new Map([
      [10, "DEBUG"],
      [20, "INFO"],
      [30, "WARNING"],
      [40, "ERROR"],
      [50, "CRITICAL"]
    ]);
    this._heartbeat_reloader = null;
    this._ajax_reloader = null;
    this._log_reloader = null;
    this._scheduled_restarter = null;
    this._action_watch_functions = new Map();
    this._action_states = new Map();
    this._clear();
    this._clear_watchers();
    this.action = new Eva_ACTION(this);
    this.lvar = new Eva_LVAR(this);
    this.evajw = null;
    this.external = {};
    this.server_info = null;
    if (typeof window !== "undefined") {
      if (typeof window.fetch !== "undefined") {
        this.external.fetch = window.fetch.bind(window);
      }
    } else if (typeof fetch !== "undefined") {
      this.external.fetch = fetch;
    } else {
      this.external.fetch = null;
    }
    if (typeof WebSocket !== "undefined") {
      this.external.WebSocket = WebSocket;
    } else {
      this.external.WebSocket = null;
    }
    if (
      typeof window !== "undefined" &&
      typeof (window as any).QRious !== "undefined"
    ) {
      this.external.QRious = (window as any).QRious;
    } else {
      this.external.QRious = null;
    }
  }

  /**
   * Register a state block
   *
   * @param name {string} block name
   * @param state_updates {boolean | Array<string>} state updates
   */
  register_state_block(name: string, state_updates: boolean | Array<string>) {
    if (name == GLOBAL_BLOCK_NAME) {
      throw new EvaError(
        EvaErrorKind.INVALID_PARAMS,
        `WebEngine state block name ${GLOBAL_BLOCK_NAME} is reserved`
      );
    }
    check_state_updates(state_updates);
    const old_block = this._blocks.get(name);
    if (old_block) {
      console.error(
        `WebEngine state block ${name} has been already registered, removing the old instance`
      );
      old_block._stop();
    }
    const block = new _EvaStateBlock(name, state_updates, this);
    if (this.logged_in) {
      block._start();
    }
    this._blocks.set(name, block);
    this._init_block(name);
  }

  /**
   * Unregister a state block
   *
   * @param name {string} block name
   */
  unregister_state_block(name: string) {
    const block = this._blocks.get(name);
    if (block) {
      block._stop();
      this._delete_block(name);
      this._blocks.delete(name);
    }
  }

  /**
   * Unregister all state blocks
   */
  unregister_all_state_blocks() {
    for (const [name, block] of this._blocks) {
      block._stop();
      this._delete_block(name);
    }
    this._blocks.clear();
  }

  bulk_request(): EvaBulkRequest {
    return new EvaBulkRequest(this);
  }

  // WASM override
  /**
   * Get engine mode
   
   * @returns "js" or "wasm"
   */
  get_mode(): string {
    return "js";
  }

  /**
   * Start the engine
   *
   * After calling the function authenticates user, opens a WebSocket (in
   * case of WS mode) or schedule AJAXs refresh interval.
   */
  start() {
    this._cancel_scheduled_restart();
    this._debug("EVA ICS WebEngine", `version: ${this.version}`);
    if (typeof fetch === "undefined") {
      this.log.error(
        '"fetch" function is unavailable. Upgrade your web browser or ' +
          "connect polyfill"
      );
      return;
    }
    if (this.logged_in) {
      this._debug("start", "already logged in");
      return;
    }
    if (this.wasm && !this.evajw) {
      this._start_evajw();
    } else {
      this._start_engine();
    }
  }
  _start_engine() {
    this._clear_last_pings();
    let q: LoginPayload = {};
    if (this.apikey) {
      q = { k: this.apikey };
      if (this.login_xopts) {
        q.xopts = this.login_xopts;
      }
      this._debug("start", "logging in with API key");
    } else if (this.password) {
      q = { u: this.login, p: this.password };
      if (this.api_token) {
        q.a = this.api_token;
      }
      if (this.login_xopts) {
        q.xopts = this.login_xopts;
      }
      this._debug("start", "logging in with password");
    } else if (this.api_token) {
      q = { a: this.api_token };
      this._debug("start", "logging in with existing auth token");
    } else if (this.set_auth_cookies) {
      let token = cookies.read("auth");
      if (token) {
        q = { a: token };
        this._debug("start", "logging in with cookie-cached auth token");
      }
    }
    if (Object.keys(q).length === 0) {
      this._debug("start", "logging in without credentials");
    }
    let user: string;
    this._api_call("login", q)
      .then((data) => {
        this.api_token = data.token;
        user = data.user;
        this._set_token_cookie();
        //if (!this.api_version) {
        //if (data.api_version) {
        //this.api_version = data.api_version;
        //} else {
        //this.api_version = 4;
        //}
        //}
        //if (this.evajw) {
        //this.evajw.set_api_version(data.api_version || 4);
        //}
        return Promise.all([
          this._load_states(this.state_updates, GLOBAL_BLOCK_NAME),
          this._heartbeat(true),
          this._start_ws(this.state_updates, GLOBAL_BLOCK_NAME)
        ]);
      })
      .then(() => {
        if (!this.ws_mode) {
          if (this._ajax_reloader) {
            clearInterval(this._ajax_reloader);
          }
          this._ajax_reloader = setInterval(() => {
            this._load_states(this.state_updates, GLOBAL_BLOCK_NAME).catch(
              () => {}
            );
          }, (this._intervals.get(IntervalKind.AjaxReload) as number) * 1000);
        } else {
          if (this._ajax_reloader) {
            clearInterval(this._ajax_reloader);
          }
          let reload = this._intervals.get(IntervalKind.Reload) as number;
          if (reload) {
            this._ajax_reloader = setInterval(() => {
              this._load_states(this.state_updates, GLOBAL_BLOCK_NAME).catch(
                () => {}
              );
            }, reload * 1000);
          }
        }
        if (this._heartbeat_reloader) {
          clearInterval(this._heartbeat_reloader);
        }
        this._heartbeat_reloader = setInterval(() => {
          this._heartbeat(false).catch(() => {});
        }, (this._intervals.get(IntervalKind.Heartbeat) as number) * 1000);
        this._debug("start", `login successful, user: ${user}`);
        this.logged_in = true;
        this.authorized_user = user;
        this._invoke_handler(EventKind.LoginSuccess);
        for (const [_, block] of this._blocks) {
          block._restart();
        }
      })
      .catch((err) => {
        this._debug("start", err);
        this.logged_in = false;
        if (err.code === undefined) {
          err.code = EvaErrorKind.OTHER;
          err.message = "Unknown error";
        }
        this._debug("start", `login failed: ${err.code} (${err.message})`);
        this._stop_engine();
        this.erase_token_cookie();
        this.error_handler(err, "login");
      });
    return true;
  }

  /**
   * Get system name
   *
   * @returns the system name or null if the engine is not logged in
   */
  system_name() {
    if (this.server_info) {
      return this.server_info.system_name;
    } else {
      return null;
    }
  }
  /**
   * Sleep the number of seconds
   *
   * @param sec {number} seconds to sleep
   */
  async sleep(sec: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, sec * 1000));
  }

  /**
   * Start log processing
   *
   * Starts log processing. The engine must be already logged in.
   *
   * @param log_level {number} log processing level (optional)
   */
  log_start(log_level?: number) {
    this._log_started = true;
    if (log_level !== undefined) {
      this.log_params.level = log_level;
    }
    if (!this.ws_mode || this._log_first_load) {
      this._log_loaded = false;
      this._load_log_entries(true);
      if (!this.ws_mode) {
        this._log_reloader = setInterval(() => {
          this._load_log_entries(false);
        }, (this._intervals.get(IntervalKind.AjaxLogReload) as number) * 1000);
      }
    }
  }

  /**
   * Set state updates without restart required
   *
   * @param state_updates {boolean} true/false or a string array
   * @param clear_existing {boolean} clear existing states
   *
   */
  async set_state_updates(
    state_updates: Array<string> | boolean,
    clear_existing?: boolean
  ) {
    check_state_updates(state_updates);
    this.state_updates = state_updates;
    const ws = this.ws.get(GLOBAL_BLOCK_NAME);
    if (ws && ws.readyState === 1) {
      let st: WsCommand = { m: "unsubscribe.state" };
      ws.send(JSON.stringify(st));
      ws.send("");
      if (this.state_updates) {
        let st: WsCommand = { m: "subscribe.state" };
        let masks;
        if (this.state_updates == true) {
          masks = ["#"];
        } else {
          masks = this.state_updates;
        }
        st.p = masks;
        ws.send(JSON.stringify(st));
        ws.send("");
      }
    }
    if (clear_existing) {
      this._clear_states(GLOBAL_BLOCK_NAME);
    }
    await this._load_states(this.state_updates, GLOBAL_BLOCK_NAME);
  }

  /**
   * Change log processing level
   *
   * @param log_level {number} log processing level
   */
  set_log_level(log_level: number) {
    this.log_params.level = log_level;
    this._set_ws_log_level(log_level);
    this._load_log_entries(true);
  }

  /**
   * Restart the engine
   *
   * e.g. used on heartbeat error or if subscription parameters are changed
   */
  restart() {
    this._cancel_scheduled_restart();
    this._debug("restart", "performing restart");
    this.stop(true)
      .then(() => {
        this._schedule_restart();
      })
      .catch(() => {
        this._schedule_restart();
      });
  }

  /**
   * Erase auth token cookie
   *
   * It is recommended to call this function when login form is displayed to
   * prevent old token caching
   */
  erase_token_cookie() {
    this.api_token = "";
    this.authorized_user = null;
    this._set_token_cookie();
  }

  /**
   * Load JSON configuration
   *
   * @param config_path {string} config path (default: config.json)
   *
   * @returns Promise object
   */
  load_config(config_path?: string): Promise<EvaConfig> {
    return new Promise((resolve, reject) => {
      const cpath = config_path || "config.json";
      this.log.debug("Eva::load_config", `loading configuration from ${cpath}`);
      this.external
        .fetch(cpath)
        .then((res: any) => res.json())
        .then((config: EvaConfig) => {
          const ec = config.engine;
          if (ec) {
            if (ec.api_uri) this.api_uri = ec.api_uri;
            if (ec.apikey) this.apikey = ec.apikey;
            if (ec.debug !== undefined) this.debug = ec.debug;
            if (ec.login) this.login = ec.login;
            if (ec.password) this.password = ec.password;
            if (ec.set_auth_cookies !== undefined)
              this.set_auth_cookies = ec.set_auth_cookies;
            if (ec.state_updates !== undefined)
              this.state_updates = ec.state_updates;
            if (ec.wasm !== undefined) this.wasm = ec.wasm;
            if (ec.ws_mode !== undefined) this.ws_mode = ec.ws_mode;
            if (ec.log_params) this.log_params = ec.log_params;
            if (ec.interval) {
              Object.keys(ec.interval).forEach((k) => {
                const key = k as IntervalKind;
                this.set_interval(key, ec.interval[key]);
              });
            }
          }
          resolve(config);
        })
        .catch((err: any) => reject(err));
    });
  }

  /**
   * Call API function
   *
   * Calls any available SFA API function
   *
   * @param method {string} API method
   * @param p1 {object} call parameters. if specified as a string/object, transformed to i=val
   * @param p2 {object} additional call parameters if p1 is a string
   *
   * @returns Promise object
   */
  async call(
    method: string,
    p1?: object | string | Array<string>,
    p2?: object
  ): Promise<any> {
    let params;
    if (typeof p1 === "string" || Array.isArray(p1)) {
      params = (p2 as any) || {};
      params.i = p1;
    } else {
      params = p1;
    }
    let p = this._prepare_call_params(params);
    return this._api_call(method, p);
  }

  /**
   * Ask server to set the token read-only (e.g. after idle)
   *
   * (EVA ICS 3.3.2+)
   *
   * the current mode can be obtained from $eva.server_info.aci.token_mode
   */
  set_readonly(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.call("session.set_readonly")
        .then(() => {
          this.server_info.aci.token_mode = "readonly";
          resolve();
        })
        .catch((err: any) => {
          reject(err);
        });
    });
  }

  /**
   * Ask server to return the token to normal mode
   *
   * (EVA ICS 3.3.2+)
   *
   * @param u {string} login
   * @param p {string} password
   * @param xopts {object} extra options (e.g. OTP)
   */
  set_normal(user?: string, password?: string, xopts?: object) {
    let q: LoginPayload = {};
    if (typeof password === "undefined" || password === null) {
      q = { k: user };
    } else {
      q = { u: user, p: password };
    }
    q.a = this.api_token;
    if (xopts !== undefined) {
      q.xopts = xopts;
    }
    this._api_call("login", q)
      .then(() => {
        this.server_info.aci.token_mode = "normal";
        this._invoke_handler(EventKind.LoginSuccess);
      })
      .catch((err: EvaError) => {
        this.error_handler(err, "set_normal");
      });
    return true;
  }

  error_handler(err: EvaError, method: string) {
    if (err.code == EvaErrorKind.ACCESS_DENIED_MORE_DATA_REQUIRED) {
      let msg = this.parse_svc_message(err.message) as any;
      msg.method = method;
      if (msg && msg.kind == "OTP") {
        switch (msg.message) {
          case "REQ":
            this._invoke_handler(EventKind.LoginOTPRequired, msg);
            return;
          case "INVALID":
            this._invoke_handler(EventKind.LoginOTPInvalid, msg);
            return;
          case "SETUP":
            this._invoke_handler(EventKind.LoginOTPSetup, msg);
            return;
        }
      }
    }
    this._invoke_handler(EventKind.LoginFailed, err);
  }

  /**
   * Set event handler function
   *
   * A single kind of event can have a single handler only
   *
   * @param event {EventKind} engine event kind
   * @param func {function} function called on event
   */
  on(event: EventKind | string, func: (...args: any[]) => void | boolean) {
    this._handlers.set(event as EventKind, func);
    this._debug("on", `setting handler for ${event}`);
    if (event == EventKind.WsEvent) {
      this._ws_handler_registered = true;
    }
  }

  /**
   * Set intervals
   *
   * @param interval_id {IntervalKind} interval kind
   * @param value {number} interval value (in seconds)
   */
  set_interval(interval_id: IntervalKind, value: number) {
    this._intervals.set(interval_id, value);
  }

  /**
   * Watch item state updates
   *
   * Registers the function to be called in case of state change event (or at
   * first state load).
   *
   * If state is already loaded, function will be called immediately. One item
   * (or item mask, set with "*") can have multiple watchers.
   *
   * @param oid {string} item oid (e.g. sensor:env/temp1, or sensor:env/\*)
   * @param func {function} function to be called
   * @param ignore_initial {boolean} skip initial state callback
   *
   */
  // WASM override
  watch(oid: string, func: (state: ItemState) => void, ignore_initial = false) {
    if (oid.includes("*")) {
      const map = this._update_state_mask_functions;
      let fcs = map?.get(oid);
      if (fcs === undefined) {
        fcs = [];
        map?.set(oid, fcs);
      }
      fcs.push(func);
      if (!ignore_initial) {
        let v = this.state(oid);
        if (Array.isArray(v)) {
          v.map(func);
        } else if (v !== undefined) {
          func(v);
        }
      }
    } else {
      const map = this._update_state_functions;
      let fcs = map?.get(oid);
      if (fcs === undefined) {
        fcs = [];
        map?.set(oid, fcs);
      }
      fcs.push(func);
      if (!ignore_initial) {
        let state = this.state(oid) as ItemState;
        if (state !== undefined) func(state);
      }
    }
  }

  /**
   * Watch action state by uuid
   *
   * Registers the function to be called in case of action status change
   * event (or at first state load).
   *
   * If status is already loaded, function will be called immediately.
   * Otherwise status is polled from the server with "action_watch" interval
   * (default: 500ms).
   *
   * There is no unwatch function as watching is stopped as soon as the
   * action is completed (or server error is occurred)
   *
   * @param uuid {string} action uuid
   * @param func {function} function to be called
   *
   */
  watch_action(uuid: string, func: (result: ActionResult | EvaError) => void) {
    let fcs = this._action_watch_functions.get(uuid);
    if (fcs === undefined) {
      fcs = [];
      this._action_watch_functions.set(uuid, fcs);
      fcs.push(func);
      const watcher = () => {
        this.call("action.result", { u: uuid })
          .then((result: ActionResult) => {
            let st = this._action_states.get(uuid);
            if (st === undefined || st.status != result.status) {
              this._action_states.set(uuid, result);
              let fcs = this._action_watch_functions.get(uuid);
              if (fcs !== undefined) {
                fcs.map((f) => f(result));
              }
            }
            if (result.finished) {
              this._action_watch_functions.delete(uuid);
              this._action_states.delete(uuid);
            } else {
              setTimeout(
                watcher,
                (this._intervals.get(IntervalKind.ActionWatch) as number) * 1000
              );
            }
          })
          .catch((err: EvaError) => {
            let fcs = this._action_watch_functions.get(uuid);
            if (fcs) {
              fcs.map((f) => f(err));
            }
            this._action_watch_functions.delete(uuid);
            this._action_states.delete(uuid);
          });
      };
      setTimeout(
        watcher,
        (this._intervals.get(IntervalKind.ActionWatch) as number) * 1000
      );
    } else {
      fcs.push(func);
      let state = this._action_states.get(uuid);
      if (state !== undefined) {
        func(state);
      }
    }
  }

  /**
   * Stop watching item state updates
   *
   * If item oid or function is not specified, all watching functions are
   * removed for a single oid (mask) or for all the items watched.
   *
   * @param oid {string} item oid (e.g. sensor:env/temp1, or sensor:env/\*)
   * @param func {function} function to be removed
   */
  unwatch(oid?: string, func?: (state: ItemState) => void) {
    if (!oid) {
      this._clear_watchers();
    } else if (!oid.includes("*")) {
      if (func) {
        this._unwatch_func(oid, func);
      } else {
        this._unwatch_all(oid);
      }
    } else {
      if (func) {
        this._unwatch_mask_func(oid, func);
      } else {
        this._unwatch_mask_all(oid);
      }
    }
  }

  // WASM override
  _unwatch_func(oid: string, func?: (state: ItemState) => void) {
    const map = this._update_state_functions;
    let fcs = map?.get(oid);
    if (fcs !== undefined) {
      map?.set(
        oid,
        fcs.filter((el) => el !== func)
      );
    }
  }

  // WASM override
  _unwatch_all(oid: string) {
    const map = this._update_state_functions;
    map?.delete(oid);
  }

  // WASM override (not supported)
  _unwatch_mask_func(oid: string, func: (state: ItemState) => void) {
    const map = this._update_state_mask_functions;
    let fcs = map?.get(oid);
    if (fcs !== undefined) {
      map?.set(
        oid,
        fcs.filter((el) => el !== func)
      );
    }
  }

  // WASM override
  _unwatch_mask_all(oid: string) {
    const map = this._update_state_mask_functions;
    map?.delete(oid);
  }

  /**
   * Get item status
   *
   * @param oid {string} item OID
   *
   * @returns item status(int) or undefined if no object found
   */
  // WASM override
  status(oid: string): number | null | undefined {
    let state = this.state(oid) as ItemState;
    if (state === undefined || state === null) return undefined;
    return state.status;
  }

  /**
   * Get item value
   *
   * @param oid {string} item OID
   *
   * @returns item value or undefined if no item found
   */
  // WASM override
  value(oid: string): any | undefined {
    let state = this.state(oid) as ItemState;
    if (state === undefined || state === null) return undefined;
    if (Number(state.value) == state.value) {
      return Number(state.value);
    } else {
      return state.value;
    }
  }

  /**
   * Get item state
   *
   * @param oid {string} item OID
   *
   * @returns state object or undefined if no item found
   */
  state(oid: string): ItemState | Array<ItemState> | undefined {
    if (!oid.includes("*")) {
      return this._state(oid);
    } else {
      return this._states_by_mask(oid);
    }
  }

  // WASM override
  _state(oid: string) {
    for (const [_, v] of this._states) {
      const state = v.get(oid);
      if (state !== undefined) return state;
    }
  }

  // WASM override
  _states_by_mask(oid_mask: string): Array<ItemState> {
    let result: Array<ItemState> = [];
    for (const [_, st] of this._states) {
      st.forEach((v, k) => {
        if (oid_mask == "*" || this._oid_match(k, oid_mask)) {
          result.push(v);
        }
      });
    }
    return result;
  }

  /**
   * Stop the engine
   *
   * After calling the function closes open WebSocket if available, stops all
   * workers then tries to close the server session
   *
   * @param keep_auth {boolean} keep authentication cookies and token
   *
   * @returns Promise object
   */
  async stop(keep_auth?: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
      this._stop_engine();
      this.logged_in = false;
      if (keep_auth) {
        resolve();
      } else if (this.api_token) {
        let token = this.api_token;
        this.erase_token_cookie();
        this._api_call("logout", { a: token })
          .then(() => {
            this.api_token = "";
            resolve();
          })
          .catch(function (err) {
            reject(err);
          });
      } else {
        resolve();
      }
    });
  }

  // ***** private functions *****
  _inject_evajw(mod: any) {
    if (mod) {
      mod.init(undefined, this).then(() => {
        mod.init_engine();
        this.evajw = mod;
        if (typeof window !== "undefined") {
          (window as any).evajw = this.evajw;
        }
        let build = mod.get_build();
        this.log.info("EVA ICS JavaScript WASM engine loaded. Build: " + build);
        try {
          mod.check_license();
        } catch (err) {
          this.log.error("License check failed. WASM engine disabled");
          this.wasm = false;
          this._start_engine();
          return;
        }
        this._clear_watchers = mod.clear_watchers;
        this._clear_states = mod.clear_states;
        this.watch = mod.watch;
        this.get_mode = mod.get_mode;
        this._unwatch_func = mod.unwatch_func;
        this._unwatch_all = mod.unwatch_all;
        this._unwatch_mask_func = mod.unwatch_mask_func;
        this._unwatch_mask_all = mod.unwatch_mask_all;
        this.status = mod.status;
        this.value = mod.value;
        this.state = mod.state;
        this._states_by_mask = mod.states_by_mask;
        this._process_loaded_states = mod.process_loaded_states;
        this._process_ws = mod.process_ws;
        this._clear_state = mod.clear_state;
        this._init_block_states = mod.init_block_states;
        this._delete_block_states = mod.delete_block_states;
        // transfer registered watchers to WASM
        function transfer_watchers(
          src: Map<string, Array<(state: ItemState) => void>>,
          mod: any
        ) {
          src.forEach((fcs, oid) => {
            fcs.forEach((f) => {
              mod.watch(oid, f, false);
            });
          });
        }
        transfer_watchers(this._update_state_functions, mod);
        transfer_watchers(this._update_state_mask_functions, mod);
        return this._start_engine();
      });
    } else {
      this.evajw = null;
      return false;
    }
  }

  _init_block(block: string) {
    this._init_block_states(block);
    this._last_ping.set(block, null);
    this._last_pong.set(block, null);
  }

  /// WASM override
  _init_block_states(block: string) {
    this._states.set(block, new Map());
  }

  _delete_block(block: string) {
    this._last_ping.delete(block);
    this._last_pong.delete(block);
    this._delete_block_states(block);
  }

  /// WASM override
  _delete_block_states(block: string) {
    this._states.delete(block);
  }

  _start_evajw() {
    this.evajw = undefined;
    const js_path = this.wasm === true ? "./evajw/evajw.js" : this.wasm;
    eval(
      `import("${js_path}?" + new Date().getTime()).catch((e)=>{this._critical("WASM module not found",1,0);this._critical(e)}).then((m)=>{this._inject_evajw(m)})`
    );
  }

  _is_ws_handler_registered() {
    return this._ws_handler_registered;
  }

  // WASM override
  _clear_watchers() {
    this._update_state_functions.clear();
    this._update_state_mask_functions.clear();
  }

  // WASM override
  _clear_states(block?: string) {
    if (block !== undefined) {
      this._states.get(block)?.clear();
    } else {
      for (let [_, v] of this._states) {
        v.clear();
      }
    }
  }

  _clear_last_pings() {
    for (const [k, _] of this._blocks) {
      this._last_ping.set(k, null);
      this._last_pong.set(k, null);
    }
  }

  _clear() {
    this._clear_watchers();
    this._clear_states();
    this._clear_last_pings();
    this.server_info = null;
    this.tsdiff = 0;
    this._log_subscribed = false;
    this._log_first_load = true;
    this._log_loaded = false;
    this._log_started = false;
    this._lr2p = [];
  }

  _critical(message: any, write_on_screen = false, throw_err = true) {
    if (write_on_screen) {
      let body = document.getElementsByTagName("body");
      if (body) {
        body[0].innerHTML = `<font color="red" size="30">${message}</font>`;
      }
    }
    this.log.critical(message);
    if (throw_err) {
      throw new Error(`critical: ${message}`);
    }
  }

  _prepare_api_call(method: string, params?: object): JsonRpcRequest {
    if (this._api_call_id == 4294967295) {
      this._api_call_id = 0;
    }
    this._api_call_id += 1;
    let id = this._api_call_id;
    if (this.debug == 2) {
      this.log.debug(method, params);
    }
    return {
      jsonrpc: "2.0",
      method: method,
      params: params,
      id: id
    };
  }

  async _api_call(method: string, params?: object): Promise<any> {
    const req = this._prepare_api_call(method, params);
    const id = req.id;
    let api_uri = `${this.api_uri}/jrpc`;
    if (this.debug) {
      api_uri += `?${method}`;
    }
    this._debug("_api_call", `${id}: ${api_uri}: ${method}`);
    return new Promise((resolve, reject) => {
      this.external
        .fetch(api_uri, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          redirect: "error",
          body: JSON.stringify(req)
        })
        .then((response: any) => {
          if (response.ok) {
            this._debug(method, `api call ${id}  success`);
            response
              .json()
              .then((data: JsonRpcResponse) => {
                if (
                  data.id != id ||
                  (data.result === undefined && data.error === undefined)
                ) {
                  reject(new EvaError(-32009, "Invalid server response", data));
                } else if (data.error) {
                  this._debug(
                    method,
                    `api call ${id} failed: ${data.error.code} (${data.error.message})`
                  );
                  reject(
                    new EvaError(data.error.code, data.error.message, data)
                  );
                } else {
                  if (this.debug == 2) {
                    this.log.debug(`API ${id} ${method} response`, data.result);
                  }
                  resolve(data.result);
                }
              })
              .catch((err: any) => {
                let code = EvaErrorKind.INVALID_DATA;
                let message = "Invalid server response";
                this._debug(
                  method,
                  `api call ${id} failed: ${code} (${message})`
                );
                reject(new EvaError(code, message, err));
              });
          } else {
            let code = EvaErrorKind.CORE_ERROR;
            let message = "Server error";
            this._debug(method, `api call ${id} failed: ${code} (${message})`);
            reject(new EvaError(code, message));
          }
        })
        .catch((err: any) => {
          let code = EvaErrorKind.CORE_ERROR;
          let message = "Server error";
          this._debug(method, `api call ${id} failed: ${code} (${message})`);
          reject(new EvaError(code, message, err));
        });
    });
  }

  async _heartbeat(on_login: boolean): Promise<void> {
    //const ws = this.ws.get(null);
    return new Promise((resolve, reject) => {
      if (on_login) {
        this._clear_last_pings();
      }
      if (this.ws_mode) {
        for (const [k, last_ping] of this._last_ping) {
          if (last_ping) {
            const last_pong = this._last_pong.get(k) || null;
            if (
              last_pong === null ||
              last_ping - last_pong >
                (this._intervals.get(IntervalKind.Heartbeat) as number)
            ) {
              this._debug(
                "heartbeat",
                `error: ws ping timeout, block ${k || GLOBAL_BLOCK_NAME}`
              );
              this._invoke_handler(EventKind.HeartBeatError);
            }
          }
        }
        if (!on_login) {
          for (const [k, ws] of this.ws) {
            if (ws && ws?.readyState >= 1) {
              this._last_ping.set(k, Date.now() / 1000);
              try {
                this._debug(
                  `block ${k || GLOBAL_BLOCK_NAME} heartbeat`,
                  "ws ping"
                );
                let payload = { m: "ping" };
                ws.send(JSON.stringify(payload));
                ws.send("");
              } catch (err) {
                this._debug("heartbeat", "error: unable to send ws ping");
                this._invoke_handler(EventKind.HeartBeatError, err);
                reject();
                return;
              }
            }
          }
        }
      }
      this.call("test")
        .then((data: any) => {
          this.server_info = data;
          this.tsdiff = new Date().getTime() / 1000 - data.time;
          this._invoke_handler(EventKind.HeartBeatSuccess);
          resolve();
        })
        .catch((err: EvaError) => {
          this._debug("heartbeat", "error: unable to send test API call");
          this._invoke_handler(EventKind.HeartBeatError, err);
        });
      this._debug("heartbeat", "ok");
    });
  }

  _load_log_entries(postprocess: boolean) {
    if (this.ws_mode) this._lr2p = [];
    this.call("log.get", {
      l: this.log_params.level,
      n: this.log_params.records
    })
      .then((data: Array<LogRecord>) => {
        if (this.ws_mode && this._log_first_load) {
          this._set_ws_log_level(this.log_params.level);
        }
        data.map((l) => this._invoke_handler(EventKind.LogRecord, l));
        this._log_loaded = true;
        this._lr2p.map((l) => this._invoke_handler(EventKind.LogRecord, l));
        if (postprocess) {
          this._invoke_handler(EventKind.LogPostProcess);
        }
        this._log_first_load = false;
      })
      .catch((err: EvaError) => {
        this.log.error(`unable to load log entries: ${err.message}`);
      });
  }

  _schedule_restart() {
    this._scheduled_restarter = setTimeout(() => {
      this.start();
    }, (this._intervals.get(IntervalKind.Restart) as number) * 1000);
  }

  _cancel_scheduled_restart() {
    if (this._scheduled_restarter) {
      clearTimeout(this._scheduled_restarter);
      this._scheduled_restarter = null;
    }
  }

  _stop_engine() {
    for (let [_, block] of this._blocks) {
      block._stop();
    }
    this._clear();
    if (this._heartbeat_reloader) {
      clearInterval(this._heartbeat_reloader);
      this._heartbeat_reloader = null;
    }
    if (this._ajax_reloader) {
      clearInterval(this._ajax_reloader);
      this._ajax_reloader = null;
    }
    if (this._log_reloader) {
      clearInterval(this._log_reloader);
      this._log_reloader = null;
    }
    const ws = this.ws.get(GLOBAL_BLOCK_NAME);
    if (ws) {
      try {
        ws.onclose = null;
        ws.onerror = function () {};
        ws.close();
      } catch (err) {
        // web socket may be still open, will close later
        setTimeout(() => {
          try {
            ws.close();
          } catch (err) {}
        }, 100);
      }
    }
  }

  _prepare_call_params(params?: any): object {
    let p = params || {};
    if (this.api_token) {
      p.k = this.api_token;
    }
    return p;
  }

  _set_token_cookie() {
    if (this.set_auth_cookies && typeof document !== "undefined") {
      [
        this.api_uri + "/ui",
        this.api_uri + "/pvt",
        this.api_uri + "/rpvt",
        this.api_uri + "/upload"
      ].map(
        (uri) =>
          (document.cookie = `auth=${this.api_token}; Path=${uri}; SameSite=Lax`),
        this
      );
    }
  }

  // WASM override
  _process_loaded_states(
    data: Array<ItemState>,
    clear_unavailable: boolean,
    block: string
  ) {
    let received_oids: string[] = [];
    if (clear_unavailable) {
      data.map((s) => {
        if (s.oid !== undefined) {
          received_oids.push(s.oid);
        }
      });
    }
    data.map((s) => this._process_state(s, clear_unavailable, block));
    if (clear_unavailable) {
      const map = this._states.get(block);
      map?.forEach((state, oid) => {
        if (
          state.status !== undefined &&
          state.status !== null &&
          !received_oids.includes(oid)
        ) {
          this._debug(`clearing unavailable item ${oid}`);
          this._clear_state(oid, block);
        }
      });
    }
  }

  async _load_states(
    state_updates: boolean | Array<string>,
    block: string
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!state_updates) {
        resolve();
      } else {
        let params: StatePayload = { full: true };
        if (state_updates == true) {
          params.i = "#";
        } else {
          params.i = state_updates;
        }
        this.call("item.state", params)
          .then((data: Array<ItemState>) => {
            this._process_loaded_states(data, this.clear_unavailable, block);
            resolve();
          })
          .catch((err: EvaError) => {
            reject(err);
          });
      }
    });
  }

  async _start_ws(
    state_updates: boolean | Array<string>,
    block: string
  ): Promise<void> {
    check_state_updates(state_updates);
    return new Promise((resolve) => {
      if (this.ws_mode) {
        let uri;
        if (!this.api_uri) {
          let loc = window.location;
          if (loc.protocol === "https:") {
            uri = "wss:";
          } else {
            uri = "ws:";
          }
          uri += "//" + loc.host;
        } else {
          uri = this.api_uri;
          if (uri.startsWith("http://")) {
            uri = uri.replace("http://", "ws://");
          } else if (uri.startsWith("https://")) {
            uri = uri.replace("https://", "wss://");
          } else {
            let loc = window.location;
            if (loc.protocol === "https:") {
              uri = "wss:";
            } else {
              uri = "ws:";
            }
            uri += "//" + loc.host + this.api_uri;
          }
        }
        let ws_uri = `${uri}/ws?`;
        if (block) {
          ws_uri += `_block=${block}&`;
        }
        ws_uri += `k=${this.api_token}`;
        let ws_buf_ttl = this._intervals.get(IntervalKind.WSBufTTL) as number;
        if (ws_buf_ttl > 0) {
          ws_uri += `&buf_ttl=${ws_buf_ttl}`;
        }
        const ws = new this.external.WebSocket(ws_uri);
        this.ws.set(block, ws);
        ws.onmessage = (evt: any) => {
          this._process_ws(evt.data, block);
        };
        ws.addEventListener("open", () => {
          this._debug("_start_ws", "ws connected");
          if (state_updates) {
            let st: WsCommand = {
              m: "subscribe.state"
            };
            let masks;
            if (state_updates == true) {
              masks = ["#"];
            } else {
              masks = state_updates;
            }
            st.p = masks;
            ws.send(JSON.stringify(st));
            ws.send("");
          }
          if (this._log_subscribed) {
            this.set_log_level(this.log_params.level);
          }
        });
      }
      resolve();
    });
  }

  _set_ws_log_level(level: number) {
    this._log_subscribed = true;
    try {
      if (this.ws) {
        let payload: WsCommand = { m: "subscribe.log", p: level };
        (this.ws.get(GLOBAL_BLOCK_NAME) as any).send(JSON.stringify(payload));
        (this.ws.get(GLOBAL_BLOCK_NAME) as any).send("");
      }
    } catch (err) {
      this._debug("log_level", "warning: unable to send ws packet", err);
    }
  }

  _process_ws_frame_pong(block: string) {
    this._last_pong.set(block, Date.now() / 1000);
  }

  _process_ws_frame_log(data: Array<LogRecord> | LogRecord) {
    if (Array.isArray(data)) {
      data.map((record) => this._preprocess_log_record(record));
    } else {
      this._preprocess_log_record(data);
    }
    this._invoke_handler(EventKind.LogPostProcess);
  }

  // WASM override
  _process_ws(payload: string, block: string) {
    let data = JSON.parse(payload);
    if (data.s == "pong") {
      this._debug("ws", "pong");
      this._process_ws_frame_pong(block);
      return;
    }
    if (block === null) {
      if (data.s == "reload") {
        this._debug("ws", "reload");
        this._invoke_handler(EventKind.ServerReload);
        return;
      }
      if (data.s == "server") {
        let ev = "server." + data.d;
        this._debug("ws", ev);
        this._invoke_handler(ev as EventKind);
        return;
      }
      if (data.s.substring(0, 11) == "supervisor.") {
        this._debug("ws", data.s);
        this._invoke_handler(data.s, data.d);
        return;
      }
      if (this._invoke_handler(EventKind.WsEvent, data) === false) return;
      if (data.s == "log") {
        this._debug("ws", "log");
        this._process_ws_frame_log(data.d);
        return;
      }
    }
    if (data.s == "state") {
      this._debug("ws", "state");
      if (Array.isArray(data.d)) {
        data.d.map(
          (state: ItemState) => this._process_state(state, true, block),
          this
        );
      } else {
        this._process_state(data.d, true, block);
      }
      return;
    }
  }

  _preprocess_log_record(record: LogRecord) {
    this._log_loaded
      ? this._invoke_handler(EventKind.LogRecord, record)
      : this._lr2p.push(record);
  }

  // WASM override
  _clear_state(oid: string, block: string) {
    this._states.get(block)?.delete(oid);
    this._process_state(
      {
        oid: oid,
        status: null,
        value: null
      },
      false,
      block
    );
  }

  _process_state(state: ItemState, is_update = false, block: string) {
    const map = this._states.get(block);
    try {
      if (state.oid === undefined) {
        return;
      }
      let oid: string = state.oid;
      let old_state = map?.get(oid);
      if (!old_state && is_update) {
        return;
      }
      if (
        // no old state
        old_state === undefined ||
        // node
        state.node != old_state.node ||
        // use ieid
        (state.ieid !== undefined &&
          (old_state.ieid === undefined ||
            state.ieid[0] == 0 ||
            old_state.ieid[0] < state.ieid[0] ||
            (old_state.ieid[0] == state.ieid[0] &&
              old_state.ieid[1] < state.ieid[1])))
      ) {
        if (old_state && (is_update || state.ieid == undefined)) {
          Object.keys(old_state).map(function (k) {
            if (!(k in state)) {
              // copy fields as-is
              (state as any)[k] = (old_state as any)[k];
            }
          });
        }
        this._debug(
          "process_state",
          `${oid} s: ${state.status} v: "${state.value}"`,
          `act: ${state.act} t: "${state.t}"`
        );
        map?.set(oid, state);
        let fcs = this._update_state_functions.get(oid);
        if (fcs) {
          fcs.map((f) => {
            try {
              f(state);
            } catch (err) {
              this.log.error(`state function processing for ${oid}:`, err);
            }
          });
        }
        this._update_state_mask_functions.forEach((fcs, k) => {
          if (this._oid_match(oid, k)) {
            fcs.map((f) => {
              try {
                f(state);
              } catch (err) {
                this.log.error(`state function processing for ${oid}:`, err);
              }
            });
          }
        });
      }
    } catch (err) {
      this.log.error("State processing error, invalid object received", err);
    }
  }

  _invoke_handler(handler: EventKind, ...args: any[]): void | boolean {
    let f = this._handlers.get(handler);
    if (f) {
      this._debug("invoke_handler", "invoking for " + handler);
      try {
        f.apply(this, args);
      } catch (err) {
        this.log.error(`handler for ${handler}:`, err);
      }
    }
  }

  _oid_match(oid: string, mask: string): boolean {
    return new RegExp("^" + mask.split("*").join(".*") + "$").test(oid);
  }

  _debug(method: string, ...data: any[]) {
    if (this.debug) {
      this.log.debug.apply(this.log, [`Eva::${method}`].concat(data));
    }
  }

  parse_svc_message(msg?: string): SvcMessage | null {
    if (msg && msg.startsWith("|")) {
      let sp = msg.split("|");
      let kind = sp[1];
      if (kind) {
        let result: SvcMessage = { kind: kind, svc: sp[2] };
        let svc_msg = sp[3];
        if (svc_msg) {
          let sp_msg = svc_msg.split("=");
          result.message = sp_msg[0];
          result.value = sp_msg[1];
        }
        return result;
      }
    }
    return null;
  }

  /**
   * OTP setup code
   *
   * @param ctx html <canvas /> element or id to generate QR code in
   * @param secret {string} OTP secret
   * @param params {OTPParams} additional parameters
   *
   * @returns QRious QR object if QR code is generated
   */
  otpQR(ctx: object | string, secret: string, params?: OTPParams) {
    if (typeof document !== "object") {
      this.log.error("document object not found");
      return;
    }
    if (!params) params = {};
    let size = params.size || 200;
    let issuer = params.issuer || `HMI ${document.location.hostname}`;
    let user = params.user || this.login;
    let value =
      "otpauth://totp/" +
      encodeURIComponent(user) +
      `?secret=${secret}&issuer=` +
      encodeURIComponent(issuer);
    if (params.xtr) {
      value += params.xtr;
    }
    return new this.external.QRious({
      element: typeof ctx === "object" ? ctx : document.getElementById(ctx),
      value: value,
      size: size
    });
  }

  /**
   * QR code for EvaHI
   *
   * Generates QR code for :doc:`EvaHI</evahi>`-compatible apps (e.g. for Eva
   * ICS Control Center mobile app for Android). Current engine session
   * must be authorized using user login. If $eva.password is defined, QR
   * code also contain password value. Requires qrious js library.
   *
   * @param ctx html <canvas /> element or id to generate QR code in
   * @param params {HiQRParams} additional parameters
   *
   * @returns QRious QR object if QR code is generated
   */
  hiQR(ctx: object | string, params?: HiQRParams) {
    if (typeof document !== "object") {
      this.log.error("document object not found");
      return;
    }
    if (!params) params = {};
    let url = params.url || document.location.href;
    let user = params.user || this.authorized_user || "";
    if (!url || !user || user.startsWith(".")) {
      return;
    }
    let password = params.password;
    if (password === undefined) {
      password = this.password;
    }
    let size = params.size || 200;
    let link = document.createElement("a");
    link.href = url;
    let protocol = link.protocol.substring(0, link.protocol.length - 1);
    let host = link.hostname;
    let port = link.port || (protocol == "http" ? "80" : "443");
    let value = `scheme:${protocol}|address:${host}|port:${port}|user:${user}`;
    if (password) {
      value += `|password:${password}`;
    }
    return new this.external.QRious({
      element: typeof ctx === "object" ? ctx : document.getElementById(ctx),
      value: value,
      size: size
    });
  }
  /**
   * Registers the global object window.$eva
   */
  register_globals() {
    if (typeof window !== "undefined") {
      (window as any).$eva = this;
    } else {
      throw new Error("the method can be started in web browsers only");
    }
  }
  /**
   * Registers global objects + legacy globals
   */
  register_legacy_globals() {
    this.register_globals();
  }
}

//const throw_no_block = () => {
//throw new EvaError(
//EvaErrorKind.INVALID_PARAMS,
//"WebEngine block not defined"
//);
//};

const check_state_updates = (state_updates: any) => {
  if (
    !Array.isArray(state_updates) &&
    state_updates !== true &&
    state_updates !== false
  ) {
    throw new EvaError(
      EvaErrorKind.INVALID_PARAMS,
      "state_updates must be an array or boolean"
    );
  }
};

export {
  Eva,
  EvaError,
  EvaErrorKind,
  EventKind,
  IntervalKind,
  ActionResult,
  ItemState,
  LogParams,
  LogRecord,
  OTPParams,
  HiQRParams,
  StateProp,
  SvcMessage,
  EvaConfig,
  EvaEngineConfig
};
