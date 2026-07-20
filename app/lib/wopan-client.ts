/**
 * WoPan (联通云盘 / 沃盘) Client for Cloudflare-Clist
 *
 * 基于 OpenList wopan-sdk-go 的 TypeScript 复刻
 * API 文档参考: https://panservice.mail.wo.cn
 */

import {
  stripLeadingSlash,
  stripTrailingSlash,
  getConfigString,
  getRefreshToken,
} from "./drive-utils";

// ==================== 类型定义 ====================

export interface DriveObject {
  key: string;
  name: string;
  size: number;
  lastModified: string;
  isDirectory: boolean;
  etag?: string;
}

export interface ListObjectsResult {
  objects: DriveObject[];
  prefixes: string[];
  isTruncated: boolean;
  nextContinuationToken?: string;
}

interface WoPanFile {
  familyId: number;
  fid: string;
  creator: string;
  size: number;
  createTime: string;
  name: string;
  shootingTime: string;
  id: string;
  type: number; // 0=directory, 1=file
  thumbUrl: string;
  fileType: string;
}

interface WoPanQueryAllFilesData {
  files: WoPanFile[];
}

interface WoPanDownloadUrlItem {
  fid: string;
  downloadUrl: string;
}

interface WoPanGetDownloadUrlV2Data {
  type: number;
  list: WoPanDownloadUrlItem[];
}

interface WoPanCreateDirectoryData {
  id: string;
}

interface WoPanUsageInfo {
  ByteTotalSize: string;
  ByteUsedSize: number;
}

interface WoPanQueryCloudUsageData {
  UsageInfo: WoPanUsageInfo;
}

interface WoPanFamilyUserCurrentData {
  DefaultHomeId: number;
}

interface WoPanRefreshTokenData {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

interface WoPanLoginData {
  needSmsCode: string;
}

interface WoPanLoginVerifyCodeData {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

interface WoPanUpload2CResp {
  code: string;
  data: {
    fid: string;
  };
  msg: string;
}

interface WoPanZoneInfo {
  zoneUrl: string;
}

// ==================== 常量 ====================

const DEFAULT_CLIENT_ID = "1001000021";
const DEFAULT_CLIENT_SECRET = "XFmi9GS2hzk98jGX";
const DEFAULT_BASE_URL = "https://panservice.mail.wo.cn";
const DEFAULT_ZONE_URL = "https://tjupload.pan.wo.cn";
const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.37";
const DEFAULT_PART_SIZE = 8 * 1024 * 1024; // 8MB

const CHANNEL_API_USER = "api-user";
const CHANNEL_WO_HOME = "wohome";
const CHANNEL_WO_CLOUD = "wocloud";

const SPACE_TYPE_PERSONAL = "0";
const SPACE_TYPE_FAMILY = "1";

const AES_IV = "wNSOYIB1k1DjY5lA";

// API keys
const KEY_PC_WEB_LOGIN = "PcWebLogin";
const KEY_PC_LOGIN_VERIFY_CODE = "PcLoginVerifyCode";
const KEY_APP_REFRESH_TOKEN = "AppRefreshToken";
const KEY_QUERY_ALL_FILES = "QueryAllFiles";
const KEY_GET_DOWNLOAD_URL_V2 = "GetDownloadUrlV2";
const KEY_CREATE_DIRECTORY = "CreateDirectory";
const KEY_RENAME_FILE_OR_DIRECTORY = "RenameFileOrDirectory";
const KEY_MOVE_FILE = "MoveFile";
const KEY_COPY_FILE = "CopyFile";
const KEY_DELETE_FILE = "DeleteFile";
const KEY_UPLOAD_2C = "upload2C";
const KEY_QUERY_CLOUD_USAGE_INFO = "QueryCloudUsageInfo";
const KEY_FAMILY_USER_CURRENT_ENCODE = "FamilyUserCurrentEncode";
const KEY_GET_ZONE_INFO = "GetZoneInfo";
const KEY_CLASSIFY_RULE = "ClassifyRule";

// ==================== AES 加密工具 ====================

async function aesEncrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    data
  );
  return new Uint8Array(encrypted);
}

async function aesDecrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    data
  );
  return new Uint8Array(decrypted);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function strToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// ==================== 加密层 ====================

class WoCrypto {
  private clientSecretKey: Uint8Array;
  private iv: Uint8Array;
  private accessKey: Uint8Array | null = null;

  constructor() {
    this.clientSecretKey = strToBytes(DEFAULT_CLIENT_SECRET);
    this.iv = strToBytes(AES_IV);
  }

  setAccessToken(token: string): void {
    if (token.length >= 16) {
      this.accessKey = strToBytes(token.substring(0, 16));
    }
  }

  async encrypt(content: string, channel: string): Promise<string> {
    const key = channel === CHANNEL_API_USER ? this.clientSecretKey : this.accessKey!;
    const data = strToBytes(content);
    const encrypted = await aesEncrypt(data, key, this.iv);
    return bytesToBase64(encrypted);
  }

  async decrypt(content: string, channel: string): Promise<string> {
    const data = base64ToBytes(content);
    const key = channel === CHANNEL_API_USER ? this.clientSecretKey : this.accessKey!;
    const decrypted = await aesDecrypt(data, key, this.iv);
    return bytesToStr(decrypted);
  }
}

// ==================== 请求工具 ====================

function calHeader(channel: string, key: string): Record<string, string> {
  const timestamp = Date.now().toString();
  return {
    appId: "10000001",
    clientId: DEFAULT_CLIENT_ID,
    method: key,
    timestamp,
    version: "1.0",
    channel,
    traceId: `${timestamp}_${Math.random().toString(36).substring(2, 8)}`,
  };
}

// ==================== 主客户端类 ====================

class WoClient {
  private crypto: WoCrypto;
  private accessToken: string;
  private refreshToken: string;
  private zoneURL: string = "";
  private zoneURLFetched = false;
  private classifyRuleData: Record<string, { type: string }> | null = null;

  constructor(refreshToken: string, accessToken: string = "") {
    this.crypto = new WoCrypto();
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    if (accessToken) {
      this.crypto.setAccessToken(accessToken);
    }
  }

  getAccessToken(): string {
    return this.accessToken;
  }

  getRefreshToken(): string {
    return this.refreshToken;
  }

  setAccessToken(token: string): void {
    this.accessToken = token;
    this.crypto.setAccessToken(token);
  }

  setRefreshToken(token: string): void {
    this.refreshToken = token;
  }

  private async request(
    channel: string,
    key: string,
    param: Record<string, any>,
    other: Record<string, any>,
    retry: boolean = true
  ): Promise<any> {
    const header = calHeader(channel, key);

    // 加密 param
    const paramJson = JSON.stringify(param);
    const encryptedParam = await this.crypto.encrypt(paramJson, channel);

    // 加密 other (如果非空)
    let encryptedOther: string | null = null;
    if (other && Object.keys(other).length > 0) {
      encryptedOther = await this.crypto.encrypt(JSON.stringify(other), channel);
    }

    const body: Record<string, any> = {
      Header: header,
      Body: {
        param: encryptedParam,
        other: encryptedOther,
      },
    };

    const url = `${DEFAULT_BASE_URL}/${channel}/dispatcher`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Origin: "https://pan.wo.cn",
      Referer: "https://pan.wo.cn/",
      "User-Agent": DEFAULT_UA,
    };
    if (this.accessToken) {
      headers["Accesstoken"] = this.accessToken;
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`WoPan request failed: ${response.status} ${response.statusText}`);
    }

    const resp = await response.json() as {
      Status: string;
      Msg?: string;
      Rsp: {
        RspCode: string;
        RspDesc: string;
        Data: string;
      };
    };

    if (resp.Status !== "200") {
      throw new Error(`WoPan API error: ${resp.Status} ${resp.Msg || ""}`);
    }

    if (resp.Rsp.RspCode !== "0000") {
      // Token 过期，尝试刷新
      if (channel !== CHANNEL_API_USER && retry && resp.Rsp.RspCode === "9999") {
        await this.doRefreshToken();
        return this.request(channel, key, param, other, false);
      }
      throw new Error(
        `WoPan API error: ${resp.Rsp.RspCode} ${resp.Rsp.RspDesc}`
      );
    }

    // 解密响应数据
    let data = resp.Rsp.Data;
    if (data && data.startsWith('"') && data.endsWith('"')) {
      data = data.substring(1, data.length - 1);
      data = await this.crypto.decrypt(data, channel);
    }

    if (!data) {
      return null;
    }

    return JSON.parse(data);
  }

  private async requestApiUser(
    key: string,
    param: Record<string, any>,
    other: Record<string, any>
  ): Promise<any> {
    return this.request(CHANNEL_API_USER, key, param, other, false);
  }

  private async requestWoHome(
    key: string,
    param: Record<string, any>,
    other: Record<string, any>
  ): Promise<any> {
    return this.request(CHANNEL_WO_HOME, key, param, other, true);
  }

  // ==================== 认证 ====================

  async pcWebLogin(phone: string, password: string): Promise<WoPanLoginData> {
    return this.requestApiUser(
      KEY_PC_WEB_LOGIN,
      {
        phone,
        password,
        uuid: "",
        verifyCode: "",
        clientSecret: DEFAULT_CLIENT_SECRET,
      },
      { clientId: DEFAULT_CLIENT_ID, clientSecret: DEFAULT_CLIENT_SECRET }
    );
  }

  async pcLoginVerifyCode(
    phone: string,
    password: string,
    messageCode: string
  ): Promise<WoPanLoginVerifyCodeData> {
    return this.requestApiUser(
      KEY_PC_LOGIN_VERIFY_CODE,
      {
        phone,
        messageCode,
        verifyCode: null,
        uuid: null,
        clientSecret: DEFAULT_CLIENT_SECRET,
        password,
      },
      { clientId: DEFAULT_CLIENT_ID, clientSecret: DEFAULT_CLIENT_SECRET }
    );
  }

  async doRefreshToken(): Promise<WoPanRefreshTokenData> {
    const result = await this.requestApiUser(
      KEY_APP_REFRESH_TOKEN,
      {
        refreshToken: this.refreshToken,
        clientSecret: DEFAULT_CLIENT_SECRET,
      },
      { clientId: DEFAULT_CLIENT_ID, clientSecret: DEFAULT_CLIENT_SECRET }
    );
    this.accessToken = result.access_token;
    this.refreshToken = result.refresh_token;
    this.crypto.setAccessToken(result.access_token);
    return result;
  }

  // ==================== 文件操作 ====================

  async queryAllFiles(
    spaceType: string,
    parentDirectoryId: string,
    pageNum: number,
    pageSize: number,
    sortRule: number,
    familyId: string
  ): Promise<WoPanQueryAllFilesData> {
    const param: Record<string, any> = {
      spaceType,
      parentDirectoryId,
      pageNum,
      pageSize,
      sortRule,
      clientId: DEFAULT_CLIENT_ID,
    };
    if (spaceType === SPACE_TYPE_FAMILY) {
      param.familyId = familyId;
    }
    return this.requestWoHome(KEY_QUERY_ALL_FILES, param, { secret: true });
  }

  async getDownloadUrlV2(fidList: string[]): Promise<WoPanGetDownloadUrlV2Data> {
    return this.requestWoHome(
      KEY_GET_DOWNLOAD_URL_V2,
      {
        type: "1",
        fidList,
        clientId: DEFAULT_CLIENT_ID,
      },
      { secret: true }
    );
  }

  async createDirectory(
    spaceType: string,
    parentDirectoryId: string,
    directoryName: string,
    familyId: string
  ): Promise<WoPanCreateDirectoryData> {
    const param: Record<string, any> = {
      spaceType,
      parentDirectoryId,
      directoryName,
      clientId: DEFAULT_CLIENT_ID,
    };
    if (spaceType === SPACE_TYPE_FAMILY) {
      param.familyId = familyId;
    }
    return this.requestWoHome(KEY_CREATE_DIRECTORY, param, { secret: true });
  }

  async renameFileOrDirectory(
    spaceType: string,
    type: number, // 1=file, 0=directory
    id: string,
    name: string,
    familyId: string,
    fileType: string = "5"
  ): Promise<void> {
    const param: Record<string, any> = {
      spaceType,
      type,
      fileType: type === 0 ? "0" : fileType,
      id,
      name,
      clientId: DEFAULT_CLIENT_ID,
    };
    if (spaceType === SPACE_TYPE_FAMILY) {
      param.familyId = familyId;
    }
    await this.requestWoHome(KEY_RENAME_FILE_OR_DIRECTORY, param, {
      secret: true,
    });
  }

  async moveFile(
    dirList: string[],
    fileList: string[],
    targetDirId: string,
    sourceType: string,
    targetType: string,
    fromFamilyId: string,
    targetFamilyId: string
  ): Promise<void> {
    const param: Record<string, any> = {
      targetDirId,
      sourceType,
      targetType,
      dirList,
      fileList,
      secret: false,
      clientId: DEFAULT_CLIENT_ID,
    };
    if (sourceType === SPACE_TYPE_FAMILY) {
      param.fromFamilyId = fromFamilyId;
    }
    if (targetType === SPACE_TYPE_FAMILY) {
      param.familyId = targetFamilyId;
    }
    await this.requestWoHome(KEY_MOVE_FILE, param, { secret: true });
  }

  async copyFile(
    dirList: string[],
    fileList: string[],
    targetDirId: string,
    sourceType: string,
    targetType: string,
    fromFamilyId: string,
    targetFamilyId: string
  ): Promise<void> {
    const param: Record<string, any> = {
      targetDirId,
      sourceType,
      targetType,
      dirList,
      fileList,
      secret: false,
      clientId: DEFAULT_CLIENT_ID,
    };
    if (sourceType === SPACE_TYPE_FAMILY) {
      param.fromFamilyId = fromFamilyId;
    }
    if (targetType === SPACE_TYPE_FAMILY) {
      param.familyId = targetFamilyId;
    }
    await this.requestWoHome(KEY_COPY_FILE, param, { secret: true });
  }

  async deleteFile(
    spaceType: string,
    dirList: string[],
    fileList: string[]
  ): Promise<void> {
    await this.requestWoHome(
      KEY_DELETE_FILE,
      {
        spaceType,
        vipLevel: "0",
        dirList,
        fileList,
        clientId: DEFAULT_CLIENT_ID,
      },
      { secret: true }
    );
  }

  async queryCloudUsageInfo(): Promise<WoPanQueryCloudUsageData> {
    return this.requestWoHome(
      KEY_QUERY_CLOUD_USAGE_INFO,
      { clientId: DEFAULT_CLIENT_ID },
      { secret: true }
    );
  }

  async familyUserCurrentEncode(): Promise<WoPanFamilyUserCurrentData> {
    return this.requestWoHome(
      KEY_FAMILY_USER_CURRENT_ENCODE,
      { clientId: DEFAULT_CLIENT_ID },
      { secret: true }
    );
  }

  async getFileType(filename: string): Promise<string> {
    const ext = filename.includes(".") ? filename.split(".").pop()!.toLowerCase() : "";
    if (!ext) return "5";

    // 尝试获取分类规则
    if (!this.classifyRuleData) {
      try {
        const data = await this.requestWoHome(
          KEY_CLASSIFY_RULE,
          { clientId: DEFAULT_CLIENT_ID },
          { secret: true }
        );
        this.classifyRuleData = data?.FileTypes || {};
      } catch {
        this.classifyRuleData = {};
      }
    }

    return this.classifyRuleData?.[ext]?.type || "5";
  }

  // ==================== 上传 ====================

  private async getZoneUrl(): Promise<string> {
    if (!this.zoneURLFetched) {
      this.zoneURLFetched = true;
      try {
        const data = await this.requestWoHome(
          KEY_GET_ZONE_INFO,
          { clientId: DEFAULT_CLIENT_ID },
          { secret: true }
        );
        if (data?.zoneUrl) {
          this.zoneURL = data.zoneUrl;
        }
      } catch {
        // 使用默认 zone URL
      }
    }
    return this.zoneURL || DEFAULT_ZONE_URL;
  }

  async upload2C(
    spaceType: string,
    file: {
      name: string;
      size: number;
      content: ReadableStream<Uint8Array>;
      contentType: string;
    },
    targetDirId: string,
    familyId: string,
    onProgress?: (current: number, total: number) => void
  ): Promise<string> {
    const zoneURL = await this.getZoneUrl();
    const batchNo = new Date()
      .toISOString()
      .replace(/[-:T.]/g, "")
      .substring(0, 14);

    const fileInfo: Record<string, any> = {
      spaceType,
      directoryId: targetDirId,
      batchNo,
      fileName: file.name,
      fileSize: file.size,
      fileType: await this.getFileType(file.name),
    };
    if (spaceType === SPACE_TYPE_FAMILY) {
      fileInfo.familyId = familyId;
    }

    const fileInfoStr = await this.crypto.encrypt(
      JSON.stringify(fileInfo),
      CHANNEL_WO_HOME
    );

    const uploadURL = `${zoneURL}/openapi/client/${KEY_UPLOAD_2C}`;
    const totalPart = Math.max(1, Math.ceil(file.size / DEFAULT_PART_SIZE));

    let fid = "";
    let finishedSize = 0;

    const reader = file.content.getReader();
    let remainingBuffer = new Uint8Array(0);

    for (let partIndex = 1; partIndex <= totalPart; partIndex++) {
      const partSize =
        partIndex === totalPart
          ? file.size - finishedSize
          : DEFAULT_PART_SIZE;

      // 收集当前分片数据
      const chunks: Uint8Array[] = [];
      let collected = 0;
      while (collected < partSize) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        collected += value.length;
        if (collected >= partSize) {
          // 如果收集多了，需要把多余部分保存
          const excess = collected - partSize;
          if (excess > 0) {
            const lastChunk = chunks[chunks.length - 1];
            const keep = lastChunk.subarray(0, lastChunk.length - excess);
            remainingBuffer = lastChunk.subarray(lastChunk.length - excess);
            chunks[chunks.length - 1] = keep;
            collected -= excess;
          }
        }
      }

      const partData = new Uint8Array(collected);
      let offset = 0;
      for (const chunk of chunks) {
        partData.set(chunk, offset);
        offset += chunk.length;
      }

      const formData = new FormData();
      formData.append(
        "uniqueId",
        `${Date.now()}_${Math.random().toString(36).substring(2, 8)}`
      );
      formData.append("accessToken", this.accessToken);
      formData.append("fileName", file.name);
      formData.append("psToken", "undefined");
      formData.append("fileSize", String(file.size));
      formData.append("totalPart", String(totalPart));
      formData.append("channel", CHANNEL_WO_CLOUD);
      formData.append("directoryId", targetDirId);
      formData.append("fileInfo", fileInfoStr);
      formData.append("partSize", String(partSize));
      formData.append("partIndex", String(partIndex));
      formData.append(
        "file",
        new Blob([partData], { type: "application/octet-stream" }),
        file.name
      );

      const resp = await fetch(uploadURL, {
        method: "POST",
        headers: {
          Origin: "https://pan.wo.cn",
          Referer: "https://pan.wo.cn/",
          "User-Agent": DEFAULT_UA,
        },
        body: formData,
      });

      if (!resp.ok) {
        throw new Error(
          `WoPan upload part ${partIndex} failed: ${resp.status}`
        );
      }

      const uploadResp = (await resp.json()) as WoPanUpload2CResp;
      if (uploadResp.code !== "0000") {
        throw new Error(
          `WoPan upload part ${partIndex} failed: ${uploadResp.code} ${uploadResp.msg}`
        );
      }

      if (uploadResp.data?.fid) {
        fid = uploadResp.data.fid;
      }

      finishedSize += partSize;
      onProgress?.(finishedSize, file.size);
    }

    reader.releaseLock();
    return fid;
  }
}

// ==================== Cloudflare-Clist 驱动接口适配 ====================

export class WopanClient {
  private config: Record<string, any>;
  private saving: Record<string, any>;
  private savingChanged = false;
  private configChanged = false;
  private client: WoClient | null = null;
  private defaultFamilyId: string = "";

  constructor(options: {
    config?: Record<string, any>;
    saving?: Record<string, any>;
  }) {
    this.config = options.config || {};
    this.saving = options.saving || {};
  }

  getStateUpdates():
    | { config?: Record<string, any>; saving?: Record<string, any> }
    | null {
    if (!this.savingChanged && !this.configChanged) {
      return null;
    }
    return {
      config: this.configChanged ? this.config : undefined,
      saving: this.savingChanged ? this.saving : undefined,
    };
  }

  private markSavingChanged(): void {
    this.savingChanged = true;
  }

  private markConfigChanged(): void {
    this.configChanged = true;
  }

  private async getClient(): Promise<WoClient> {
    if (this.client) {
      return this.client;
    }

    const refreshToken =
      getConfigString(this.config, "refresh_token") ||
      getConfigString(this.saving, "refresh_token");
    if (!refreshToken) {
      throw new Error("WoPan: missing refresh_token");
    }

    const accessToken = getConfigString(this.saving, "access_token");
    this.client = new WoClient(refreshToken, accessToken);

    // 初始化：获取 familyId
    try {
      const fml = await this.client.familyUserCurrentEncode();
      this.defaultFamilyId = String(fml.DefaultHomeId);
    } catch {
      // 可能没有家庭云，忽略
    }

    return this.client;
  }

  private getSpaceType(): string {
    return this.config.family_id ? SPACE_TYPE_FAMILY : SPACE_TYPE_PERSONAL;
  }

  private getFamilyId(): string {
    return this.config.family_id || this.defaultFamilyId || "";
  }

  private createTimeToISO(createTime: string): string {
    // 格式: 20230607214351 (UTC+8)
    if (createTime.length !== 14) return createTime;
    const y = createTime.substring(0, 4);
    const m = createTime.substring(4, 6);
    const d = createTime.substring(6, 8);
    const h = createTime.substring(8, 10);
    const min = createTime.substring(10, 12);
    const s = createTime.substring(12, 14);
    // 转换为 ISO 格式，标记为 UTC+8
    return `${y}-${m}-${d}T${h}:${min}:${s}+08:00`;
  }

  // ==================== 文件操作接口 ====================

  async listObjects(
    prefix: string = "",
    _delimiter: string = "/",
    _maxKeys: number = 1000,
    continuationToken?: string
  ): Promise<ListObjectsResult> {
    const client = await this.getClient();
    const spaceType = this.getSpaceType();
    const familyId = this.getFamilyId();

    const pageNum = continuationToken ? parseInt(continuationToken, 10) : 0;
    const pageSize = 100;
    const sortRule = this.getSortRule();

    // 解析路径，找到对应的目录 ID
    const normalized = stripLeadingSlash(prefix || "");
    const dirId = normalized ? await this.findDirectoryId(client, normalized, spaceType, familyId) : "0";

    if (!dirId && normalized) {
      return { objects: [], prefixes: [], isTruncated: false };
    }

    const data = await client.queryAllFiles(
      spaceType,
      dirId || "0",
      pageNum,
      pageSize,
      sortRule,
      familyId
    );

    const objects: DriveObject[] = [];
    const prefixes: string[] = [];
    const keyBase = normalized ? `${stripTrailingSlash(normalized)}/` : "";

    for (const file of data.files || []) {
      const isDirectory = file.type === 0;
      const key = isDirectory
        ? `${keyBase}${file.name}/`
        : `${keyBase}${file.name}`;
      objects.push({
        key,
        name: file.name,
        size: file.size || 0,
        lastModified: this.createTimeToISO(file.createTime),
        isDirectory,
        etag: file.fid,
      });
      if (isDirectory) {
        prefixes.push(key);
      }
    }

    const isTruncated = (data.files || []).length >= pageSize;
    return {
      objects: objects.sort((a, b) => {
        if (a.isDirectory !== b.isDirectory) {
          return a.isDirectory ? -1 : 1;
        }
        return a.name.localeCompare(b.name);
      }),
      prefixes,
      isTruncated,
      nextContinuationToken: isTruncated ? String(pageNum + 1) : undefined,
    };
  }

  private async findDirectoryId(
    client: WoClient,
    path: string,
    spaceType: string,
    familyId: string
  ): Promise<string | null> {
    const parts = path.split("/").filter(Boolean);
    let currentId = "0";

    for (const part of parts) {
      let found = false;
      let pageNum = 0;
      while (true) {
        const data = await client.queryAllFiles(
          spaceType,
          currentId,
          pageNum,
          100,
          1,
          familyId
        );
        const match = (data.files || []).find(
          (f) => f.name === part && f.type === 0
        );
        if (match) {
          currentId = match.id;
          found = true;
          break;
        }
        if ((data.files || []).length < 100) break;
        pageNum++;
      }
      if (!found) return null;
    }
    return currentId;
  }

  private async findFileId(
    client: WoClient,
    path: string,
    spaceType: string,
    familyId: string
  ): Promise<{ id: string; fid: string; isDir: boolean } | null> {
    const normalized = stripLeadingSlash(path);
    if (!normalized) return null;

    const parts = normalized.split("/");
    const fileName = parts.pop() || "";
    const parentPath = parts.join("/");

    let parentId = "0";
    if (parentPath) {
      const found = await this.findDirectoryId(client, parentPath, spaceType, familyId);
      if (!found) return null;
      parentId = found;
    }

    let pageNum = 0;
    while (true) {
      const data = await client.queryAllFiles(
        spaceType,
        parentId,
        pageNum,
        100,
        1,
        familyId
      );
      const match = (data.files || []).find((f) => f.name === fileName);
      if (match) {
        return {
          id: match.id,
          fid: match.fid,
          isDir: match.type === 0,
        };
      }
      if ((data.files || []).length < 100) break;
      pageNum++;
    }
    return null;
  }

  async getObject(key: string): Promise<Response> {
    const client = await this.getClient();
    const fileInfo = await this.findFileId(
      client,
      key,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!fileInfo || fileInfo.isDir) {
      throw new Error("WoPan file not found");
    }

    const downloadData = await client.getDownloadUrlV2([fileInfo.fid]);
    if (!downloadData.list || downloadData.list.length === 0) {
      throw new Error("WoPan download URL not found");
    }

    const downloadUrl = downloadData.list[0].downloadUrl;
    return fetch(downloadUrl, {
      headers: {
        "User-Agent": DEFAULT_UA,
      },
    });
  }

  async getSignedUrl(key: string): Promise<string> {
    const client = await this.getClient();
    const fileInfo = await this.findFileId(
      client,
      key,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!fileInfo || fileInfo.isDir) {
      throw new Error("WoPan file not found");
    }

    const downloadData = await client.getDownloadUrlV2([fileInfo.fid]);
    if (!downloadData.list || downloadData.list.length === 0) {
      throw new Error("WoPan download URL not found");
    }

    return downloadData.list[0].downloadUrl;
  }

  async headObject(
    key: string
  ): Promise<{
    contentLength: number;
    contentType: string;
    lastModified: string;
  } | null> {
    const client = await this.getClient();
    const fileInfo = await this.findFileId(
      client,
      key,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!fileInfo) return null;

    // 获取目录列表找到文件信息
    const normalized = stripLeadingSlash(key);
    const parts = normalized.split("/");
    const fileName = parts.pop() || "";
    const parentPath = parts.join("/");

    let parentId = "0";
    if (parentPath) {
      parentId =
        (await this.findDirectoryId(
          client,
          parentPath,
          this.getSpaceType(),
          this.getFamilyId()
        )) || "0";
    }

    let pageNum = 0;
    while (true) {
      const data = await client.queryAllFiles(
        this.getSpaceType(),
        parentId,
        pageNum,
        100,
        1,
        this.getFamilyId()
      );
      const match = (data.files || []).find((f) => f.name === fileName);
      if (match) {
        return {
          contentLength: match.size || 0,
          contentType: "application/octet-stream",
          lastModified: this.createTimeToISO(match.createTime),
        };
      }
      if ((data.files || []).length < 100) break;
      pageNum++;
    }
    return null;
  }

  async putObject(
    key: string,
    body: ArrayBuffer | string,
    contentType?: string
  ): Promise<void> {
    const client = await this.getClient();
    const normalized = stripLeadingSlash(key);
    const parts = normalized.split("/");
    const fileName = parts.pop() || "upload";
    const parentPath = parts.join("/");

    let parentId = "0";
    if (parentPath) {
      const found = await this.findDirectoryId(
        client,
        parentPath,
        this.getSpaceType(),
        this.getFamilyId()
      );
      if (!found) {
        throw new Error("WoPan parent directory not found");
      }
      parentId = found;
    }

    const data = typeof body === "string" ? strToBytes(body) : new Uint8Array(body);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(data);
        controller.close();
      },
    });

    await client.upload2C(
      this.getSpaceType(),
      {
        name: fileName,
        size: data.length,
        content: stream,
        contentType: contentType || "application/octet-stream",
      },
      parentId,
      this.getFamilyId(),
      undefined
    );
  }

  async deleteObject(key: string): Promise<void> {
    const client = await this.getClient();
    const fileInfo = await this.findFileId(
      client,
      key,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!fileInfo) return;

    const dirList: string[] = [];
    const fileList: string[] = [];
    if (fileInfo.isDir) {
      dirList.push(fileInfo.id);
    } else {
      fileList.push(fileInfo.id);
    }

    await client.deleteFile(this.getSpaceType(), dirList, fileList);
  }

  async createFolder(folderPath: string): Promise<void> {
    const client = await this.getClient();
    const normalized = stripTrailingSlash(stripLeadingSlash(folderPath));
    const parts = normalized.split("/");
    const folderName = parts.pop() || "New Folder";
    const parentPath = parts.join("/");

    let parentId = "0";
    if (parentPath) {
      const found = await this.findDirectoryId(
        client,
        parentPath,
        this.getSpaceType(),
        this.getFamilyId()
      );
      if (!found) {
        throw new Error("WoPan parent directory not found");
      }
      parentId = found;
    }

    await client.createDirectory(
      this.getSpaceType(),
      parentId,
      folderName,
      this.getFamilyId()
    );
  }

  async copyObject(sourceKey: string, destKey: string): Promise<void> {
    const client = await this.getClient();
    const srcInfo = await this.findFileId(
      client,
      sourceKey,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!srcInfo) {
      throw new Error("WoPan source not found");
    }

    const normalized = stripLeadingSlash(destKey);
    const parts = normalized.split("/");
    const destFileName = parts.pop() || "copy";
    const parentPath = parts.join("/");

    let parentId = "0";
    if (parentPath) {
      const found = await this.findDirectoryId(
        client,
        parentPath,
        this.getSpaceType(),
        this.getFamilyId()
      );
      if (!found) {
        throw new Error("WoPan destination not found");
      }
      parentId = found;
    }

    const dirList: string[] = [];
    const fileList: string[] = [];
    if (srcInfo.isDir) {
      dirList.push(srcInfo.id);
    } else {
      fileList.push(srcInfo.id);
    }

    await client.copyFile(
      dirList,
      fileList,
      parentId,
      this.getSpaceType(),
      this.getSpaceType(),
      this.getFamilyId(),
      this.getFamilyId()
    );

    // 如果需要重命名
    const srcName = stripLeadingSlash(sourceKey).split("/").pop() || "";
    if (destFileName !== srcName && !srcInfo.isDir) {
      // 需要找到复制后的文件并重命名
      // WoPan copy 不支持直接改名，这里先复制再重命名
      let pageNum = 0;
      while (true) {
        const data = await client.queryAllFiles(
          this.getSpaceType(),
          parentId,
          pageNum,
          100,
          1,
          this.getFamilyId()
        );
        const match = (data.files || []).find(
          (f) => f.name === srcName &&
            f.createTime ===
              (await this.getFileCreateTime(client, srcInfo.id))
        );
        if (match && match.name !== destFileName) {
          await client.renameFileOrDirectory(
            this.getSpaceType(),
            srcInfo.isDir ? 0 : 1,
            match.id,
            destFileName,
            this.getFamilyId()
          );
          break;
        }
        if ((data.files || []).length < 100) break;
        pageNum++;
      }
    }
  }

  private async getFileCreateTime(
    client: WoClient,
    fileId: string
  ): Promise<string> {
    // 查找文件创建时间 - 通过遍历父目录
    // 这里简化处理
    return "";
  }

  async renameObject(path: string, newName: string): Promise<void> {
    const client = await this.getClient();
    const fileInfo = await this.findFileId(
      client,
      path,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!fileInfo) {
      throw new Error("WoPan file not found");
    }

    await client.renameFileOrDirectory(
      this.getSpaceType(),
      fileInfo.isDir ? 0 : 1,
      fileInfo.id,
      newName,
      this.getFamilyId()
    );
  }

  async moveObject(path: string, destPath: string): Promise<void> {
    const client = await this.getClient();
    const srcInfo = await this.findFileId(
      client,
      path,
      this.getSpaceType(),
      this.getFamilyId()
    );
    if (!srcInfo) {
      throw new Error("WoPan source not found");
    }

    const normalizedDest = stripTrailingSlash(stripLeadingSlash(destPath));
    const parentPath = normalizedDest.includes("/")
      ? normalizedDest.substring(0, normalizedDest.lastIndexOf("/"))
      : "";

    let parentId = "0";
    if (parentPath) {
      const found = await this.findDirectoryId(
        client,
        parentPath,
        this.getSpaceType(),
        this.getFamilyId()
      );
      if (!found) {
        throw new Error("WoPan destination not found");
      }
      parentId = found;
    }

    const dirList: string[] = [];
    const fileList: string[] = [];
    if (srcInfo.isDir) {
      dirList.push(srcInfo.id);
    } else {
      fileList.push(srcInfo.id);
    }

    await client.moveFile(
      dirList,
      fileList,
      parentId,
      this.getSpaceType(),
      this.getSpaceType(),
      this.getFamilyId(),
      this.getFamilyId()
    );

    // 如果需要重命名
    const newName = normalizedDest.split("/").pop() || "";
    const oldName = stripLeadingSlash(path).split("/").pop() || "";
    if (newName && newName !== oldName) {
      await client.renameFileOrDirectory(
        this.getSpaceType(),
        srcInfo.isDir ? 0 : 1,
        srcInfo.id,
        newName,
        this.getFamilyId()
      );
    }
  }

  // ==================== 上传接口（简化版） ====================

  async initiateMultipartUpload(
    _key: string,
    _contentType: string,
    _options?: { size?: number; chunkSize?: number }
  ): Promise<string> {
    // WoPan 使用 upload2C 自动分片，不需要手动初始化
    return `wopan_${Date.now()}`;
  }

  async getSignedUploadPartUrl(
    _key: string,
    _uploadId: string,
    _partNumber: number
  ): Promise<string> {
    // WoPan 不支持直接分片 URL
    throw new Error("WoPan does not support signed upload part URLs");
  }

  async uploadPart(
    _key: string,
    _uploadId: string,
    _partNumber: number,
    _body: ReadableStream,
    _contentLength: number
  ): Promise<string> {
    // WoPan 不支持独立分片上传
    throw new Error("WoPan does not support individual part upload");
  }

  async completeMultipartUpload(
    _key: string,
    _uploadId: string,
    _parts: { partNumber: number; etag: string }[]
  ): Promise<void> {
    // WoPan 不需要完成上传
  }

  async abortMultipartUpload(
    _key: string,
    _uploadId: string
  ): Promise<void> {
    // WoPan 不需要中止上传
  }

  // ==================== 辅助方法 ====================

  private getSortRule(): number {
    const rule = this.config.sort_rule || "name_asc";
    const ruleMap: Record<string, number> = {
      name_asc: 1,
      name_desc: 2,
      size_asc: 3,
      size_desc: 4,
      time_asc: 5,
      time_desc: 6,
    };
    return ruleMap[rule] || 1;
  }

  /**
   * 获取存储空间使用情况
   */
  async getStorageDetails(): Promise<{
    totalSpace: number;
    usedSpace: number;
  }> {
    const client = await this.getClient();
    const quota = await client.queryCloudUsageInfo();
    return {
      totalSpace: parseInt(quota.UsageInfo.ByteTotalSize, 10) || 0,
      usedSpace: quota.UsageInfo.ByteUsedSize || 0,
    };
  }
}