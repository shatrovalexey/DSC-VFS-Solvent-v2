/* ==========================================================================
   dsc-vfs-solvent — клиентская логика веб-интерфейса (Vue 3 + TypeScript).

   Vue импортируется из локального пакета «vue» и собирается в единый
   бандл (esbuild). CDN не используется, типы Vue берутся из node_modules.
   ========================================================================== */

import { createApp, defineComponent } from "vue";

const API = "/api";

// -- Типы данных API ------------------------------------------------------

interface AuthUser {
  id: number;
  username: string;
  is_admin: boolean;
  banned: boolean;
  banned_at: string | null;
  banned_until: string | null;
  email_confirmed: boolean;
  must_change_password: boolean;
}

interface AuthResponse {
  token: string;
  user: AuthUser;
}

interface FileItem {
  id: number;
  name: string;
  size: number;
  created_at: string;
}

interface AccountItem {
  id: number;
  driver: string;
  host: string;
  login: string;
  enabled: boolean;
  nodes_count: number;
}

interface AdminUser {
  id: number;
  username: string;
  is_admin: boolean;
  banned: boolean;
  banned_at: string | null;
  banned_until: string | null;
}

// -- Хранилище ключа пользователя ----------------------------------------
// Ключ пользователя генерируется на клиенте и хранится ТОЛЬКО в localStorage.
// На сервер передаётся зашифрованным открытым RSA-ключом (RSA-OAEP).
function generateUserKey(): string {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function importPublicKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

async function encryptUserKey(key: string, publicKeyPem: string): Promise<string> {
  const pub = await importPublicKey(publicKeyPem);
  const enc = new TextEncoder().encode(key);
  const cipher = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, enc);
  const bytes = new Uint8Array(cipher);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// -- Приложение Vue ------------------------------------------------------

createApp(
  defineComponent({
    data() {
      return {
        // Авторизация
        token: localStorage.getItem("token") || "",
        currentUser: null as AuthUser | null,
        userKey: localStorage.getItem("userKey") || "",

        // Приватное состояние (ключи с "_" Vue не делает реактивными)
        _serverPublicKeyCache: null as string | null,
        _toastTimer: undefined as ReturnType<typeof setTimeout> | undefined,

        // Формы
        loginUsername: "",
        loginPassword: "",
        regUsername: "",
        regPassword: "",
        verifyCode: "",
        needVerify: false,
        // Смена пароля
        newPass: "",
        newPassConfirm: "",
        showChangePassword: false,
        oldPassword: "",
        // Удаление аккаунта
        showDeleteAccount: false,
        deletePassword: "",
        accDriver: "ftp",
        accHost: "",
        accPort: "",
        accLogin: "",
        accPass: "",
        accPath: "",
        adminSearch: "",

        // Данные
        files: [] as FileItem[],
        accounts: [] as AccountItem[],
        adminUsers: [] as AdminUser[],

        // Состояние
        loading: false,
        uploading: false,
        dragActive: false,
        toastMessage: "",
        toastError: false,
      };
    },

    computed: {
      isAuthed(): boolean {
        return Boolean(this.token && this.currentUser);
      },
      isAdmin(): boolean {
        return Boolean(this.currentUser && this.currentUser.is_admin);
      },
    },

    methods: {
      // -- Утилиты -------------------------------------------------------
      formatSize(bytes: number): string {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(2) + " MB";
      },

      formatBanDate(value: string | null): string {
        if (!value) return "";
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) return value;
        return d.toLocaleString("ru-RU", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
      },

      // -- HTTP ----------------------------------------------------------
      async api(path: string, options: RequestInit = {}): Promise<any> {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          ...(options.headers as Record<string, string> | undefined),
        };
        if (this.token) headers["Authorization"] = "Bearer " + this.token;
        if (
          this.userKey &&
          path !== "/auth/login" &&
          path !== "/auth/register"
        ) {
          const publicKeyPem = await this.getServerPublicKey();
          headers["X-VFS-Key"] = await encryptUserKey(this.userKey, publicKeyPem);
        }
        const res = await fetch(API + path, { ...options, headers });
        if (!res.ok) {
          let detail = res.statusText;
          try {
            detail = (await res.json()).detail || detail;
          } catch (e) {
            /* ignore */
          }
          throw new Error(detail);
        }
        if (res.status === 204) return null;
        const ct = res.headers.get("content-type") || "";
        return ct.includes("application/json") ? res.json() : res;
      },

      async getServerPublicKey(): Promise<string> {
        if (this._serverPublicKeyCache) return this._serverPublicKeyCache;
        const data = await fetch(API + "/auth/public-key").then((r) => r.json());
        this._serverPublicKeyCache = data.public_key;
        return this._serverPublicKeyCache;
      },

      toast(msg: string, isError = false): void {
        this.toastMessage = msg;
        this.toastError = isError;
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => {
          this.toastMessage = "";
        }, 3500);
      },

      // -- Авторизация ---------------------------------------------------
      handleAuthResponse(data: AuthResponse): void {
        this.token = data.token;
        this.currentUser = data.user;
        localStorage.setItem("token", this.token);
        localStorage.setItem("user", JSON.stringify(this.currentUser));
        if (!localStorage.getItem("userKey")) {
          localStorage.setItem("userKey", generateUserKey());
        }
        this.userKey = localStorage.getItem("userKey") || "";
        this.loadAll();
        if (this.isAdmin) this.adminLoadUsers();
        if (this.currentUser && this.currentUser.must_change_password) {
          this.showChangePassword = true;
          this.oldPassword = "";
          this.newPass = "";
          this.newPassConfirm = "";
          this.toast("Требуется сменить пароль", true);
        }
      },

      async login(): Promise<void> {
        const username = this.loginUsername.trim();
        const password = this.loginPassword;
        if (!username || !password) {
          this.toast("Введите e-mail и пароль", true);
          return;
        }
        try {
          const data = await this.api("/auth/login", {
            method: "POST",
            body: JSON.stringify({ username, password }),
          });
          this.handleAuthResponse(data);
          this.toast("Добро пожаловать!");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async register(): Promise<void> {
        const username = this.regUsername.trim();
        const password = this.regPassword;
        if (!username || !password) {
          this.toast("Введите e-mail и пароль", true);
          return;
        }
        try {
          await this.api("/auth/register", {
            method: "POST",
            body: JSON.stringify({ username, password }),
          });
          this.loginUsername = username;
          this.needVerify = true;
          this.toast("Код подтверждения отправлен на e-mail");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async verifyEmail(): Promise<void> {
        if (!this.verifyCode.trim()) {
          this.toast("Введите код из письма", true);
          return;
        }
        try {
          const data = await this.api("/auth/verify", {
            method: "POST",
            body: JSON.stringify({
              username: this.loginUsername.trim(),
              code: this.verifyCode.trim(),
            }),
          });
          this.handleAuthResponse(data);
          this.needVerify = false;
          this.verifyCode = "";
          this.toast("E-mail подтверждён");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async forgotPassword(): Promise<void> {
        const username = this.loginUsername.trim();
        if (!username) {
          this.toast("Введите e-mail", true);
          return;
        }
        try {
          await this.api("/auth/forgot-password", {
            method: "POST",
            body: JSON.stringify({ username }),
          });
          this.toast("Новый пароль отправлен на e-mail. Смените его при входе");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async changePassword(): Promise<void> {
        if (this.newPass !== this.newPassConfirm) {
          this.toast("Пароли не совпадают", true);
          return;
        }
        try {
          await this.api("/auth/change-password", {
            method: "POST",
            body: JSON.stringify({
              old_password: this.oldPassword,
              new_password: this.newPass,
            }),
          });
          this.showChangePassword = false;
          this.oldPassword = "";
          this.newPass = "";
          this.newPassConfirm = "";
          if (this.currentUser) this.currentUser.must_change_password = false;
          this.toast("Пароль изменён");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async deleteAccount(): Promise<void> {
        if (!confirm("Удалить аккаунт? Все файлы будут уничтожены безвозвратно!")) {
          return;
        }
        try {
          await this.api("/auth/delete-account", {
            method: "POST",
            body: JSON.stringify({ password: this.deletePassword }),
          });
          this.toast("Аккаунт удалён");
          this.logout();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async logout(): Promise<void> {
        try {
          await this.api("/auth/logout", { method: "POST", body: "{}" });
        } catch (e) {
          /* ignore */
        }
        this.token = "";
        this.currentUser = null;
        this.userKey = "";
        this.files = [];
        this.accounts = [];
        this.adminUsers = [];
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        localStorage.removeItem("userKey");
        this.toast("Выход выполнен");
      },

      // -- Файлы ---------------------------------------------------------
      async loadFiles(): Promise<void> {
        this.loading = true;
        try {
          this.files = await this.api("/files");
        } catch (e) {
          this.toast((e as Error).message, true);
        } finally {
          this.loading = false;
        }
      },

      async loadAll(): Promise<void> {
        try {
          await Promise.all([this.loadFiles(), this.loadAccounts()]);
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      onFileInputChange(): void {
        const input = this.$refs.fileInput as HTMLInputElement | undefined;
        if (!input || !input.files || !input.files.length) return;
        this.uploadFile(input.files[0]);
        input.value = "";
      },

      async uploadForm(): Promise<void> {
        const input = this.$refs.fileInputForm as HTMLInputElement | undefined;
        if (!input || !input.files || !input.files.length) {
          this.toast("Выберите файл", true);
          return;
        }
        await this.uploadFile(input.files[0]);
        input.value = "";
      },

      onDragOver(): void {
        this.dragActive = true;
      },

      onDragLeave(): void {
        this.dragActive = false;
      },

      onDrop(event: DragEvent): void {
        this.dragActive = false;
        const files = event.dataTransfer?.files;
        if (!files || !files.length) {
          this.toast("Не удалось получить файл", true);
          return;
        }
        this.uploadFile(files[0]);
      },

      async uploadFile(file: File): Promise<void> {
        if (this.uploading) {
          this.toast("Дождитесь окончания текущей загрузки", true);
          return;
        }
        const fd = new FormData();
        fd.append("file", file);
        this.uploading = true;
        try {
          await this.api("/files", { method: "POST", headers: {}, body: fd });
          this.toast("Файл загружен");
          await this.loadFiles();
        } catch (e) {
          this.toast((e as Error).message, true);
        } finally {
          this.uploading = false;
        }
      },

      async download(id: number): Promise<void> {
        try {
          const res = await fetch(`${API}/files/${id}/download`, {
            headers: { Authorization: "Bearer " + this.token },
          });
          if (!res.ok) throw new Error((await res.json()).detail || "Ошибка");
          const blob = await res.blob();
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "file-" + id;
          a.click();
          URL.revokeObjectURL(a.href);
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async removeFile(id: number): Promise<void> {
        try {
          await this.api("/files/" + id, { method: "DELETE" });
          this.toast("Файл удалён");
          await this.loadFiles();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      // -- Аккаунты ------------------------------------------------------
      async loadAccounts(): Promise<void> {
        try {
          this.accounts = await this.api("/accounts");
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async addAccount(): Promise<void> {
        const payload = {
          driver: this.accDriver,
          host: this.accHost,
          port: parseInt(this.accPort || "0", 10),
          login: this.accLogin,
          password: this.accPass,
          path: this.accPath,
        };
        if (!payload.host || !payload.login) {
          this.toast("Укажите хост и логин", true);
          return;
        }
        try {
          await this.api("/accounts", { method: "POST", body: JSON.stringify(payload) });
          this.toast("Аккаунт добавлен");
          this.accHost = "";
          this.accPort = "";
          this.accLogin = "";
          this.accPass = "";
          this.accPath = "";
          await this.loadAccounts();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async removeAccount(id: number): Promise<void> {
        const acc = this.accounts.find((a) => a.id === id);
        const nodesCount = acc ? acc.nodes_count || 0 : 0;
        const otherEnabled = this.accounts.some((a) => a.id !== id && a.enabled);

        if (nodesCount > 0 && !otherEnabled) {
          if (
            !confirm(
              "Удалить аккаунт?\n\nВНИМАНИЕ: хранящиеся в нём файлы будут недоступны!",
            )
          ) {
            return;
          }
        } else if (nodesCount > 0) {
          if (
            !confirm(
              `В этом аккаунте хранится ${nodesCount} частей файлов.\n\n` +
                "При удалении части будут перенесены в другие доступные аккаунты.\n" +
                "Продолжить удаление?",
            )
          ) {
            return;
          }
        } else {
          if (!confirm("Удалить аккаунт?")) return;
        }

        try {
          const res = await this.api("/accounts/" + id, { method: "DELETE" });
          this.toast(res.message || "Аккаунт удалён");
          await this.loadAccounts();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      // -- Администрирование --------------------------------------------
      async adminLoadUsers(): Promise<void> {
        if (!this.isAdmin) return;
        const q = this.adminSearch.trim();
        try {
          this.adminUsers = await this.api(
            "/admin/users" + (q ? "?q=" + encodeURIComponent(q) : ""),
          );
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      adminClearSearch(): void {
        this.adminSearch = "";
        this.adminLoadUsers();
      },

      async adminBan(id: number): Promise<void> {
        if (!confirm("Забанить пользователя?")) return;
        try {
          const res = await this.api(`/admin/users/${id}/ban`, {
            method: "POST",
            body: "{}",
          });
          this.toast(res.message || "Пользователь забанен");
          await this.adminLoadUsers();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },

      async adminUnban(id: number): Promise<void> {
        try {
          const res = await this.api(`/admin/users/${id}/unban`, {
            method: "POST",
            body: "{}",
          });
          this.toast(res.message || "Пользователь разбанен");
          await this.adminLoadUsers();
        } catch (e) {
          this.toast((e as Error).message, true);
        }
      },
    },

    async mounted(): Promise<void> {
      const storedUser = localStorage.getItem("user");
      if (this.token && storedUser) {
        try {
          this.currentUser = JSON.parse(storedUser);
          await this.api("/auth/me");
          await this.loadAll();
          if (this.isAdmin) await this.adminLoadUsers();
        } catch (e) {
          this.token = "";
          this.currentUser = null;
          localStorage.clear();
        }
      }
    },
  }),
).mount("#app");