/**
 * Minimal structural HTTP types so callers (SCA, GitHub Action) can inject
 * a fake client in tests without depending on undici/Response internals.
 */
export interface HttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<HttpResponse>;
