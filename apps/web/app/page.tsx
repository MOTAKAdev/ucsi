'use client';

import React, { FormEvent, useEffect, useMemo, useRef, useState } from 'react';

type Result = {
  rank: number;
  sni: string;
  target: string;
  ip?: string;
  status: 'READY' | 'NOT_READY';
  reason?: string;
  tcp_connect_ms?: number;
  tls_handshake_ms?: number;
  latency_ms?: number;
  server_to_sni_ms?: number;
  stability: number;
  tls13: boolean;
  http2: boolean;
  sni_accepted: boolean;
  certificate_valid: boolean;
  certificate_subject?: string;
  certificate_issuer?: string;
  certificate_expires_at?: string;
  certificate_sans?: string[];
  alpn?: string;
  http_status?: number;
  http_protocol?: string;
  redirects: number;
  redirect_target?: string;
  x25519?: boolean | null;
  post_quantum?: boolean | null;
  http3?: boolean | null;
  http3_advertised: boolean;
  http3_handshake_ms?: number;
  server_p95_ms?: number;
  jitter_ms?: number;
  ranking_score?: number;
  evidence_score?: number;
  confidence?: string;
};

type AutoResponse = {
  origin_ip: string;
  origin?: string;
  candidates_scanned: number;
  qualified_count?: number;
  results: Result[];
  duration_ms?: number;
};

type ApiError = { error?: { message?: string; code?: string } };

let ucsiPageInstance = '';

function getUCSIPageInstance() {
  if (!ucsiPageInstance) {
    ucsiPageInstance =
      typeof crypto !== 'undefined' &&
      typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  return ucsiPageInstance;
}

type ScanStage =
  | 'idle'
  | 'server'
  | 'client'
  | 'finalizing'
  | 'complete';

type RankedResult = Result & {
  client_delay_ms?: number;
  final_score?: number;
};

async function api(
  path: string,
  init?: RequestInit,
) {
  const headers = new Headers(init?.headers);

  headers.set(
    'Content-Type',
    'application/json',
  );

  headers.set(
    'x-ucsi-page-instance',
    getUCSIPageInstance(),
  );

  const response = await fetch(
    `/api/ucsi${path}`,
    {
      ...init,
      headers,
      cache: 'no-store',
    },
  );

  const text = await response.text();

  let data: unknown = null;

  try {
    data = text
      ? JSON.parse(text)
      : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    const body =
      data as ApiError | null;

    const error = new Error(
      body?.error?.message ||
        body?.error?.code ||
        `Request failed (${response.status})`,
    );

    (
      error as Error & {
        retryAfter?: number;
      }
    ).retryAfter = Number(
      response.headers.get(
        'retry-after',
      ) || 0,
    );

    throw error;
  }

  return data;
}

function validIPv4(value: string): string | null {
  const v = value.trim();
  const p = v.split('.');

  if (
    p.length !== 4 ||
    p.some((x) => !/^\d{1,3}$/.test(x))
  ) {
    return 'Enter a valid public IPv4 address.';
  }

  const n = p.map(Number);

  if (n.some((x) => x < 0 || x > 255)) {
    return 'Each IPv4 octet must be between 0 and 255.';
  }

  if (
    v === '0.0.0.0' ||
    v === '255.255.255.255' ||
    n[0] === 127 ||
    n[0] === 10 ||
    (n[0] === 172 && n[1] >= 16 && n[1] <= 31) ||
    (n[0] === 192 && n[1] === 168) ||
    (n[0] === 169 && n[1] === 254) ||
    n[0] >= 224
  ) {
    return 'Use the server public IPv4. Private, loopback, multicast and 0.0.0.0 are not valid.';
  }

  return null;
}

function validHostname(value: string, label: string): string | null {
  const v = value.trim().toLowerCase();

  if (!v) return `${label} is required.`;
  if (v.length > 253) return `${label} is too long.`;

  if (
    v.includes('://') ||
    v.includes('/') ||
    v.includes(' ')
  ) {
    return `${label} must be a hostname only.`;
  }

  const h = v.endsWith('.') ? v.slice(0, -1) : v;

  if (
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
      h,
    )
  ) {
    return `${label} must be a valid hostname such as example.com.`;
  }

  return null;
}

function ms(v?: number | null) {
  return typeof v === 'number' &&
    Number.isFinite(v) &&
    v > 0
    ? `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms`
    : '—';
}

function stabilityTone(v: number) {
  if (v >= 0.9) return 'good';
  if (v >= 0.7) return 'mid';
  return 'bad';
}

function stability(v: number) {
  return `${Math.round(
    Math.max(0, Math.min(1, v)) * 100,
  )}%`;
}

function relativeTone(
  value?: number,
  best?: number,
) {
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    value <= 0
  ) {
    return 'unknown';
  }

  if (
    typeof best === 'number' &&
    best > 0
  ) {
    const ratio = value / best;

    if (ratio <= 1.2) return 'good';
    if (ratio <= 1.6) return 'mid';
    return 'bad';
  }

  return 'unknown';
}

function sleep(msValue: number) {
  return new Promise<void>((resolve) =>
    window.setTimeout(resolve, msValue),
  );
}

async function measureClientDelay(
  sni: string,
  samples = 3,
): Promise<number | null> {
  const values: number[] = [];

  for (let i = 0; i < samples; i += 1) {
    const controller = new AbortController();

    const timer = window.setTimeout(
      () => controller.abort(),
      4500,
    );

    const start = performance.now();

    try {
      const probeURL =
        `https://${sni}/?` +
        `ucsi_client_probe=${Date.now()}-${i}-${Math.random()
          .toString(36)
          .slice(2)}`;

      await fetch(probeURL, {
        method: 'GET',
        mode: 'no-cors',
        cache: 'no-store',
        redirect: 'follow',
        credentials: 'omit',
        signal: controller.signal,
      });

      const elapsed = performance.now() - start;

      if (
        Number.isFinite(elapsed) &&
        elapsed > 0
      ) {
        values.push(elapsed);
      }
    } catch {
      // Browser-side network failure is treated as an unavailable
      // client measurement for this SNI.
    } finally {
      window.clearTimeout(timer);
    }

    await sleep(35);
  }

  if (!values.length) return null;

  values.sort((a, b) => a - b);

  return values.length % 2 === 1
    ? values[Math.floor(values.length / 2)]
    : (values[values.length / 2 - 1] +
        values[values.length / 2]) /
        2;
}

function isReadyResult(result: Result) {
  return (
    (result.status === 'READY' || result.status == null) &&
    result.tls13 === true &&
    result.http2 === true &&
    result.alpn === 'h2' &&
    result.sni_accepted === true &&
    result.certificate_valid === true &&
    result.x25519 === true &&
    result.post_quantum === true &&
    result.http3 === true &&
    result.http3_advertised === true &&
    Number(result.stability) >= 1
  );
}

function rankResults(
  results: Result[],
  clientDelays: Record<string, number>,
): RankedResult[] {
  // The API already returns server-qualified candidates in `results`.
  // Do not re-filter them in the browser: browser/runtime field differences
  // must not turn a valid server result into a false NO MATCH.
  const eligible = results;

  if (!eligible.length) return [];

  const serverValues = eligible
    .map((r) => r.server_to_sni_ms ?? r.latency_ms ?? 0)
    .filter((v) => v > 0);

  const clientValues = eligible
    .map((r) => clientDelays[r.sni])
    .filter(
      (v) =>
        typeof v === 'number' &&
        Number.isFinite(v) &&
        v > 0,
    );

  const bestServer = Math.min(
    ...(serverValues.length ? serverValues : [1]),
  );

  const bestClient = Math.min(
    ...(clientValues.length ? clientValues : [1]),
  );

  const clientAvailable = clientValues.length > 0;

  return eligible
    .map((result) => {
      const server =
        result.server_to_sni_ms ??
        result.latency_ms ??
        0;

      const client = clientDelays[result.sni];

      const serverNorm =
        server > 0 ? server / bestServer : 9;

      const clientNorm =
        typeof client === 'number' && client > 0
          ? client / bestClient
          : clientAvailable
            ? 9
            : 1;

      const stabilityPenalty =
        1 - Math.max(
          0,
          Math.min(1, result.stability),
        );

      const score =
        clientAvailable
          ? clientNorm * 0.65 +
            serverNorm * 0.30 +
            stabilityPenalty * 0.05
          : serverNorm * 0.90 +
            stabilityPenalty * 0.10;

      return {
        ...result,
        client_delay_ms: client,
        final_score: score,
      };
    })
    .sort((a, b) => {
      if (
        (a.final_score ?? 999) !==
        (b.final_score ?? 999)
      ) {
        return (
          (a.final_score ?? 999) -
          (b.final_score ?? 999)
        );
      }

      return (
        (a.client_delay_ms ?? Infinity) -
        (b.client_delay_ms ?? Infinity)
      );
    })
    .slice(0, 3)
    .map((result, index) => ({
      ...result,
      rank: index + 1,
    }));
}

function Diamond() {
  return (
    <svg
      viewBox="0 0 32 30"
      className="diamond"
      aria-hidden="true"
    >
      <path d="M4 8 8 3h16l4 5-12 19L4 8Z" />
      <path d="M4 8h24M8 3l8 5 8-5M10 8l6 19 6-19" />
    </svg>
  );
}

function CopyIcon({
  copied,
}: {
  copied: boolean;
}) {
  return copied ? (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path d="m5 12 4 4L19 6" />
    </svg>
  ) : (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <rect
        x="9"
        y="8"
        width="10"
        height="11"
        rx="2"
      />
      <path d="M15 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3" />
    </svg>
  );
}

function Check({
  ok,
  label,
}: {
  ok: boolean;
  label: string;
}) {
  return (
    <span className={`check ${ok ? 'ok' : 'bad'}`}>
      <i />
      {label}
    </span>
  );
}

function shortIssuer(value?: string) {
  const v = value || '';

  if (/google trust services/i.test(v)) {
    return 'Google Trust Services';
  }

  if (/let'?s encrypt/i.test(v)) {
    return "Let's Encrypt";
  }

  const cn = v.match(/CN=([^,]+)/i);
  return cn?.[1] || v || 'Unknown issuer';
}

function ResultCard({
  result,
  bestClient,
  bestServer,
  copied,
  onCopy,
}: {
  result: RankedResult;
  bestClient?: number;
  bestServer?: number;
  copied: string;
  onCopy: (value: string, key: string) => void;
}) {
  const clientTone = relativeTone(
    result.client_delay_ms,
    bestClient,
  );

  const serverTone = relativeTone(
    result.server_to_sni_ms ?? result.latency_ms,
    bestServer,
  );

  const certIssuer = shortIssuer(
    result.certificate_issuer,
  );

  const ready = isReadyResult(result);

  return (
    <article
      className={[
        'result-card',
        ready ? 'ready-card' : '',
        ready && result.rank === 1
          ? 'best-card'
          : '',
      ].join(' ')}
    >
      <div className="result-heading">
        <div
          className={[
            'rank',
            ready && result.rank === 1
              ? 'top-rank'
              : '',
          ].join(' ')}
        >
          #{result.rank}
        </div>

        <div className="address-pair">
          <div
            className={`address-group sni-group ${
              copied === `sni-${result.rank}`
                ? 'address-copied'
                : ''
            }`}
          >
            <span className="label">
              SNI
            </span>

            <div className="address-line">
              <strong>
                {result.sni}
              </strong>

              <button
                type="button"
                className={`copy-icon ${
                  copied === `sni-${result.rank}`
                    ? 'copied'
                    : ''
                }`}
                aria-label="Copy SNI"
                title={
                  copied === `sni-${result.rank}`
                    ? 'Copied'
                    : 'Copy SNI'
                }
                onClick={() =>
                  onCopy(
                    result.sni,
                    `sni-${result.rank}`,
                  )
                }
              >
                <CopyIcon
                  copied={
                    copied ===
                    `sni-${result.rank}`
                  }
                />
              </button>
            </div>
          </div>

          <div className="address-group target-group">
            <span className="label">
              TARGET
            </span>

            <div className="target-address">
              <span className="target-value">
                {result.target}
              </span>

              <button
                type="button"
                className="copy-icon"
                aria-label="Copy target"
                title="Copy target"
                onClick={() =>
                  onCopy(
                    result.target,
                    `target-${result.rank}`,
                  )
                }
              >
                <CopyIcon
                  copied={
                    copied ===
                    `target-${result.rank}`
                  }
                />
              </button>
            </div>
          </div>
        </div>

        <span
          className={`verdict ${ready ? 'ready' : 'bad'}`}
        >
          <i />
          {ready ? 'READY' : 'NOT READY'}
        </span>
      </div>

      <div className="performance">
        <div
          className={`metric client-delay ${clientTone}`}
        >
          <span>CLIENT → SNI</span>
          <strong>
            {ms(result.client_delay_ms)}
          </strong>
          <small>
            {typeof result.client_delay_ms === 'number' &&
            Number.isFinite(result.client_delay_ms) &&
            result.client_delay_ms > 0
              ? 'from your browser'
              : 'not measured'}
          </small>
        </div>

        <div
          className={`metric server-delay ${serverTone}`}
        >
          <span>SERVER → SNI</span>
          <strong>
            {ms(
              result.server_to_sni_ms ??
                result.latency_ms,
            )}
          </strong>
          <small>
            median · p95 {ms(result.server_p95_ms)}
          </small>
        </div>

        <div
          className={`metric stability ${stabilityTone(
            result.stability,
          )}`}
        >
          <span>STABILITY</span>
          <strong>
            {stability(result.stability)}
          </strong>
          <small>
            repeat success
          </small>
        </div>

        <div
          className={`metric tls-metric ${
            result.tls13 &&
            result.http2 &&
            result.alpn === 'h2'
              ? 'good'
              : 'unknown'
          }`}
        >
          <span>PROTOCOL</span>
          <strong>
            {result.http2 && result.alpn === 'h2'
              ? 'HTTP/2'
              : result.tls13
                ? 'TLS 1.3'
                : '—'}
          </strong>
          <small>
            {result.tls13
              ? result.http2 && result.alpn === 'h2'
                ? result.http3 === true
                  ? 'TLS 1.3 + h2 + h3'
                  : 'TLS 1.3 + h2'
                : 'TLS 1.3'
              : 'Protocol not established'}
          </small>
        </div>
      </div>

      <div className="checks">
        <Check
          ok={result.tls13}
          label="TLS 1.3"
        />
        <Check
          ok={
            result.http2 &&
            result.alpn === 'h2'
          }
          label="HTTP/2 · h2"
        />
        <Check
          ok={result.x25519 === true}
          label="X25519"
        />
        <Check
          ok={result.post_quantum === true}
          label="X25519MLKEM768 · PQ"
        />
        <Check
          ok={result.http3 === true}
          label="HTTP/3 · QUIC"
        />
        <Check
          ok={result.http3_advertised}
          label="HTTP/3 · Alt-Svc"
        />
        <Check
          ok={result.certificate_valid}
          label={`Certificate · ${certIssuer}`}
        />
      </div>

      <div className="evidence-line">
        <span>ALPN</span>
        <b>{result.alpn || '—'}</b>

        <span>SERVER</span>
        <b>{result.ip || '—'}</b>

        <span>H3</span>
        <b>
          {result.http3 === true
            ? `${ms(result.http3_handshake_ms)}`
            : result.http3_advertised
              ? 'handshake failed'
              : 'not advertised'}
        </b>

        <span>CERT</span>
        <b>
          {result.certificate_expires_at
            ? `expires ${new Date(
                result.certificate_expires_at,
              )
                .toISOString()
                .slice(0, 10)}`
            : result.certificate_valid
              ? 'valid'
              : '—'}
        </b>
      </div>

      <div className="selection-line">
        <span className="selection-dot" />
        {ready
          ? result.rank === 1
            ? 'Best measured match from this scan'
            : `Final position #${result.rank} after client + server measurements`
          : `Not ready · ${result.reason || 'mandatory checks failed'}`}
      </div>
    </article>
  );
}

export default function Home() {
  const [mode, setMode] = useState<
    'auto' | 'manual'
  >('auto');

  const [serverIP, setServerIP] =
    useState('');

  const [manualSNI, setManualSNI] =
    useState('');

  const [manualTarget, setManualTarget] =
    useState('');

  const [manualPort, setManualPort] =
    useState(443);

  const [auto, setAuto] =
    useState<AutoResponse | null>(null);

  const [finalAutoResults, setFinalAutoResults] =
    useState<RankedResult[]>([]);

  const [manual, setManual] =
    useState<Result | null>(null);

  const [clientDelays, setClientDelays] =
    useState<Record<string, number>>({});

  const [
    clientDelayLoading,
    setClientDelayLoading,
  ] = useState<Record<string, boolean>>({});

  const [clientMeasuredCount, setClientMeasuredCount] =
    useState(0);

  const [clientRankingBusy, setClientRankingBusy] =
    useState(false);

  const [busy, setBusy] =
    useState(false);

  const [error, setError] =
    useState('');

  const [cooldown, setCooldown] =
    useState(0);

  const [copied, setCopied] =
    useState('');

  const [scanStage, setScanStage] =
    useState<ScanStage>('idle');

  const scanAbortRef =
    useRef<AbortController | null>(null);

  useEffect(() => {
    const cancelActiveScan = () => {
      scanAbortRef.current?.abort();
      scanAbortRef.current = null;
    };

    window.addEventListener(
      'pagehide',
      cancelActiveScan,
    );

    window.addEventListener(
      'beforeunload',
      cancelActiveScan,
    );

    return () => {
      window.removeEventListener(
        'pagehide',
        cancelActiveScan,
      );

      window.removeEventListener(
        'beforeunload',
        cancelActiveScan,
      );

      cancelActiveScan();
    };
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;

    const timer = window.setInterval(() => {
      setCooldown((value) => Math.max(0, value - 1));
    }, 1000);

    return () => window.clearInterval(timer);
  }, [cooldown]);

  useEffect(() => {
    if (!auto?.results?.length) {
      setClientRankingBusy(false);
      setFinalAutoResults([]);
      setClientDelays({});
      setClientDelayLoading({});
      setClientMeasuredCount(0);
      return;
    }

    let cancelled = false;

    async function runClientMeasurements() {
      const pool = auto?.results ?? [];

      const serverReady = pool;

      // Show server-qualified candidates immediately. Client measurements
      // refine the ranking, but a browser-side measurement failure must not
      // turn a valid server result into "NO MATCH".
      setFinalAutoResults(
        serverReady.slice(0, 3).map((result, index) => ({
          ...result,
          rank: index + 1,
        })),
      );

      setClientRankingBusy(true);
      setScanStage('client');
      setClientMeasuredCount(0);

      const initialLoading: Record<
        string,
        boolean
      > = Object.fromEntries(
        pool.map((result) => [
          result.sni,
          true,
        ]),
      );

      setClientDelayLoading(initialLoading);
      setClientDelays({});

      const delays: Record<
        string,
        number
      > = {};

      let cursor = 0;

      async function worker() {
        while (!cancelled) {
          const index = cursor++;

          if (index >= pool.length) {
            return;
          }

          const candidate = pool[index];

          const delay =
            await measureClientDelay(
              candidate.sni,
              3,
            );

          if (cancelled) return;

          if (
            typeof delay === 'number' &&
            Number.isFinite(delay)
          ) {
            delays[candidate.sni] = delay;

            setClientDelays((prev) => ({
              ...prev,
              [candidate.sni]: delay,
            }));
          }

          setClientDelayLoading(
            (prev) => ({
              ...prev,
              [candidate.sni]: false,
            }),
          );

          setClientMeasuredCount(
            (value) =>
              Math.min(
                pool.length,
                value + 1,
              ),
          );
        }
      }

      await Promise.all(
        Array.from(
          {
            length: Math.min(
              5,
              pool.length,
            ),
          },
          () => worker(),
        ),
      );

      if (cancelled) return;

      setScanStage('finalizing');

      await sleep(220);

      if (cancelled) return;

      const ranked =
        rankResults(pool, delays);

      setFinalAutoResults(ranked);
      setClientRankingBusy(false);
      setScanStage('complete');
    }

    runClientMeasurements();

    return () => {
      cancelled = true;
    };
  }, [auto]);

  const stagePercent = useMemo(() => {
    if (scanStage === 'server') return 0;
    if (scanStage === 'client') {
      if (!auto || !auto.results.length) return 38;

      return Math.min(
        88,
        38 +
          Math.round(
            (clientMeasuredCount /
              auto.results.length) *
              50,
          ),
      );
    }

    if (scanStage === 'finalizing') return 96;
    if (scanStage === 'complete') return 100;

    return 0;
  }, [
    scanStage,
    clientMeasuredCount,
    auto,
  ]);

  const bestClient = useMemo(() => {
    const values = finalAutoResults
      .map((r) => r.client_delay_ms)
      .filter(
        (v): v is number =>
          typeof v === 'number' &&
          Number.isFinite(v) &&
          v > 0,
      );

    return values.length
      ? Math.min(...values)
      : undefined;
  }, [finalAutoResults]);

  const bestServer = useMemo(() => {
    const values = finalAutoResults
      .map(
        (r) =>
          r.server_to_sni_ms ??
          r.latency_ms,
      )
      .filter(
        (v): v is number =>
          typeof v === 'number' &&
          Number.isFinite(v) &&
          v > 0,
      );

    return values.length
      ? Math.min(...values)
      : undefined;
  }, [finalAutoResults]);

  const stageText = () => {
    if (scanStage === 'server') {
      return 'Analyzing server path · TLS · HTTP/2 · HTTP/3 · certificate · key exchange';
    }

    if (scanStage === 'client') {
      const total =
        auto?.results?.length || 0;

      return `Measuring your connection to ${total} candidates · ${clientMeasuredCount}/${total}`;
    }

    if (scanStage === 'finalizing') {
      return 'Comparing all measurements and selecting the final Top 3';
    }

    if (scanStage === 'complete') {
      return 'Measurement complete · final ranking is based on client + server results';
    }

    return 'Ready for a new scan';
  };

  function resetResults() {
    setAuto(null);
    setManual(null);
    setFinalAutoResults([]);
    setClientDelays({});
    setClientDelayLoading({});
    setClientMeasuredCount(0);
    setError('');
    setScanStage('idle');
  }

  async function runAuto(
  event: FormEvent,
) {
  event.preventDefault();
  setError('');

  if (cooldown > 0) {
    setError(
      `Please wait ${cooldown}s before starting another scan.`,
    );
    return;
  }

  const ipError =
    validIPv4(serverIP);

  if (ipError) {
    setError(ipError);
    return;
  }

  scanAbortRef.current?.abort();

  const controller =
    new AbortController();

  scanAbortRef.current =
    controller;

  setBusy(true);
  resetResults();
  setScanStage('server');

  try {
    const response =
      (await api(
        '/api/v1/origin/scan',
        {
          method: 'POST',
          body: JSON.stringify({
            server_ip:
              serverIP.trim(),
            samples: 3,
            top_n: 15,
          }),
          signal:
            controller.signal,
        },
      )) as AutoResponse;

    if (controller.signal.aborted) {
      return;
    }

    setAuto(response);
    setCooldown(5);
  } catch (e) {
    const err =
      e as Error & {
        retryAfter?: number;
      };

    if (
      controller.signal.aborted ||
      err.name === 'AbortError'
    ) {
      setError('');
      setScanStage('idle');
      return;
    }

    if (
      err.retryAfter &&
      err.retryAfter > 0
    ) {
      setCooldown(
        err.retryAfter,
      );
    }

    setScanStage('idle');

    setError(
      err.message ||
        'Scan failed.',
    );
  } finally {
    if (
      scanAbortRef.current ===
      controller
    ) {
      scanAbortRef.current =
        null;
    }

    setBusy(false);
  }
}

  async function runManual(
  event: FormEvent,
) {
  event.preventDefault();
  setError('');

  if (cooldown > 0) {
    setError(
      `Please wait ${cooldown}s before starting another scan.`,
    );
    return;
  }

  const ipError =
    validIPv4(serverIP);

  if (ipError) {
    setError(ipError);
    return;
  }

  const sniError =
    validHostname(
      manualSNI,
      'SNI',
    );

  if (sniError) {
    setError(sniError);
    return;
  }

  const targetError =
    validHostname(
      manualTarget,
      'Target',
    );

  if (targetError) {
    setError(targetError);
    return;
  }

  if (manualPort !== 443) {
    setError(
      'Port must be 443 for TLS/SNI scanning.',
    );
    return;
  }

  scanAbortRef.current?.abort();

  const controller =
    new AbortController();

  scanAbortRef.current =
    controller;

  setBusy(true);
  resetResults();
  setScanStage('server');

  try {
    setManual(
      (await api(
        '/api/v1/origin/manual',
        {
          method: 'POST',
          body: JSON.stringify({
            server_ip:
              serverIP.trim(),
            sni:
              manualSNI.trim(),
            target:
              manualTarget.trim(),
            port: 443,
            samples: 3,
          }),
          signal:
            controller.signal,
        },
      )) as Result,
    );

    if (controller.signal.aborted) {
      return;
    }

    setCooldown(5);
    setScanStage('complete');
  } catch (e) {
    const err =
      e as Error & {
        retryAfter?: number;
      };

    if (
      controller.signal.aborted ||
      err.name === 'AbortError'
    ) {
      setError('');
      setScanStage('idle');
      return;
    }

    if (
      err.retryAfter &&
      err.retryAfter > 0
    ) {
      setCooldown(
        err.retryAfter,
      );
    }

    setScanStage('idle');

    setError(
      err.message ||
        'Manual scan failed.',
    );
  } finally {
    if (
      scanAbortRef.current ===
      controller
    ) {
      scanAbortRef.current =
        null;
    }

    setBusy(false);
  }
}

  function copyText(
    value: string,
    key: string,
  ) {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(key);

        window.setTimeout(
          () => setCopied(''),
          1200,
        );
      })
      .catch(() =>
        setError(
          'Clipboard access was blocked by the browser.',
        ),
      );
  }

  const isScanning =
    busy || clientRankingBusy;

  return (
    <div
      className={[
        'app',
        isScanning
          ? 'scan-active'
          : '',
      ].join(' ')}
    >
      <header className="topbar">
        <div className="brand">
          <span className="brand-icon">
            <Diamond />
          </span>

          <div>
            <strong>Pikify</strong>
            <span>
              SNI Intelligence (Beta)
            </span>
          </div>
        </div>
      </header>

      <main className="main">
        <section className="intro">
          <span className="eyebrow">
            SNI SCANNER
          </span>

          <h1>
            Find the best SNI for your
            server.
          </h1>

          <p>Live SNI measurements for your server.</p>
        </section>

        <section className="scanner-card">
          <div className="mode-switch" role="tablist">
            <button
              type="button"
              className={
                mode === 'auto'
                  ? 'active'
                  : ''
              }
              onClick={() => {
                setMode('auto');
                resetResults();
              }}
            >
              Automatic
            </button>

            <button
              type="button"
              className={
                mode === 'manual'
                  ? 'active'
                  : ''
              }
              onClick={() => {
                setMode('manual');
                resetResults();
              }}
            >
              Manual
            </button>
          </div>

          {mode === 'auto' ? (
            <form
              className="form auto-form"
              onSubmit={runAuto}
            >
              <label className="field server-field">
                <span>
                  SERVER IPv4
                </span>

                <input
                  value={serverIP}
                  onChange={(e) =>
                    setServerIP(
                      e.target.value,
                    )
                  }
                  placeholder="0.0.0.0"
                  inputMode="decimal"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={isScanning}
                />
              </label>

              <button
                className="scan-button"
                type="submit"
                disabled={
                  isScanning ||
                  cooldown > 0
                }
              >
                <span>
                  {isScanning
                    ? 'Scanning…'
                    : cooldown > 0
                      ? `Wait ${cooldown}s`
                      : 'Find Top 3 SNI'}
                </span>

                <b>→</b>
              </button>
            </form>
          ) : (
            <form
              className="form manual-form"
              onSubmit={runManual}
            >
              <label className="field server-field">
                <span>
                  SERVER IPv4
                </span>

                <input
                  value={serverIP}
                  onChange={(e) =>
                    setServerIP(
                      e.target.value,
                    )
                  }
                  placeholder="0.0.0.0"
                  inputMode="decimal"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={isScanning}
                />
              </label>

              <label className="field sni-field">
                <span>
                  SNI / SERVER NAME
                </span>

                <input
                  value={manualSNI}
                  onChange={(e) =>
                    setManualSNI(
                      e.target.value,
                    )
                  }
                  placeholder="example.com"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={isScanning}
                />
              </label>

              <label className="field target-field">
                <span>
                  TARGET
                </span>

                <input
                  aria-label="Target"
                  value={manualTarget}
                  onChange={(e) =>
                    setManualTarget(
                      e.target.value,
                    )
                  }
                  placeholder="example.com"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={isScanning}
                />
              </label>

              <label className="field port-field">
                <span>PORT</span>

                <input
                  value={manualPort}
                  onChange={(e) =>
                    setManualPort(
                      Number(
                        e.target.value,
                      ) || 0,
                    )
                  }
                  type="number"
                  min={1}
                  max={65535}
                  inputMode="numeric"
                  disabled={isScanning}
                />
              </label>

              <button
                className="scan-button"
                type="submit"
                disabled={
                  isScanning ||
                  cooldown > 0
                }
              >
                <span>
                  {isScanning
                    ? 'Scanning…'
                    : cooldown > 0
                      ? `Wait ${cooldown}s`
                      : 'Test SNI'}
                </span>

                <b>→</b>
              </button>
            </form>
          )}

          {error && (
            <div
              className="error"
              role="alert"
            >
              {error}
            </div>
          )}

          {isScanning && (
            <div className="scanner-progress">
              <div className="progress-top">
                <span>
                  {stageText()}
                </span>

                <strong>
                  {scanStage === 'server'
                    ? 'SCANNING'
                    : stagePercent + '%'}
                </strong>
              </div>

              <div className="progress-track">
                <div
                  className={'progress-value' + (scanStage === 'server' ? ' indeterminate' : '')}
                  style={scanStage === 'server' ? undefined : { width: stagePercent + '%' }}
                />
              </div>

              <div className="stage-points">
                <span
                  className={
                    scanStage ===
                      'server' ||
                    clientRankingBusy
                      ? 'active'
                      : ''
                  }
                >
                  SERVER
                </span>

                <span
                  className={
                    scanStage ===
                      'client'
                      ? 'active'
                      : ''
                  }
                >
                  CLIENT
                </span>

                <span
                  className={
                    scanStage ===
                      'finalizing'
                      ? 'active'
                      : ''
                  }
                >
                  RANKING
                </span>
              </div>
            </div>
          )}
        </section>

        {auto &&
          scanStage === 'complete' &&
          !clientRankingBusy &&
          finalAutoResults.length === 0 && (
            <section className="results no-match">
              <div className="results-head">
                <div>
                  <span className="eyebrow">
                    NO MATCH
                  </span>

                  <h2>
                    No SNI passed the full
                    requirement set.
                  </h2>
                </div>
              </div>
            </section>
          )}

        {auto &&
          scanStage === 'complete' &&
          !clientRankingBusy &&
          finalAutoResults.length > 0 && (
            <section className="results results-reveal">
              <div className="results-head">
                <div>
                  <span className="eyebrow">
                    FINAL SELECTION
                  </span>

                  <h2>
                    Top 3 SNI
                  </h2>

                  <p className="results-subtitle">
                    Ranked after server-side
                    validation and live
                    client measurements.
                  </p>
                </div>

                <span className="results-meta">
                  {auto.candidates_scanned}{' '}
                  checked ·{' '}
                  {auto.qualified_count ??
                    auto.results.length}{' '}
                  qualified
                </span>
              </div>

              <div className="result-list">
                {finalAutoResults.map(
                  (result) => (
                    <div
                      key={`${result.rank}-${result.sni}`}
                    >
                      <ResultCard
                        result={result}
                        bestClient={
                          bestClient
                        }
                        bestServer={
                          bestServer
                        }
                        copied={copied}
                        onCopy={
                          copyText
                        }
                      />
                    </div>
                  ),
                )}
              </div>
            </section>
          )}

        {manual &&
          !clientRankingBusy && (
            <section className="results results-reveal">
              <div className="results-head">
                <div>
                  <span className="eyebrow">
                    MEASURED
                  </span>

                  <h2>
                    Manual result
                  </h2>

                  <p className="results-subtitle">
                    Direct server-side
                    measurement.
                  </p>
                </div>
              </div>

              <div className="result-list">
                <div>
                  <ResultCard
                    result={{
                      ...manual,
                      client_delay_ms:
                        undefined,
                    }}
                    bestServer={
                      manual.server_to_sni_ms ??
                      manual.latency_ms
                    }
                    copied={copied}
                    onCopy={copyText}
                  />
                </div>
              </div>
            </section>
          )}
      </main>

      <footer>
        <span>
          © 2026 MOTAKAdev. All rights reserved. • Pikify
        </span>
      </footer>
    </div>
  );
}
