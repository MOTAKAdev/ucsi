import { NextRequest } from 'next/server';

const upstream =
  process.env.UCSI_INTERNAL_API ||
  'http://localhost:8080';

const token =
  process.env.UCSI_API_TOKEN || '';

const COOLDOWN_MS = 5 * 1000;

const buckets =
  new Map<string, number>();

let activeScans = 0;

function clientKey(request: NextRequest) {
  return (
    request.headers.get(
      'x-ucsi-page-instance',
    ) ||
    request.headers.get(
      'cf-connecting-ip',
    ) ||
    request.headers.get(
      'x-real-ip',
    ) ||
    request.headers
      .get('x-forwarded-for')
      ?.split(',')[0]
      ?.trim() ||
    'unknown'
  );
}

function isScanPath(path: string) {
  return (
    path === '/api/v1/origin/scan' ||
    path === '/api/v1/origin/manual'
  );
}

function guard(request: NextRequest) {
  const key = clientKey(request);
  const now = Date.now();
  const last = buckets.get(key) || 0;

  if (activeScans >= 1) {
    return {
      allowed: false,
      retryAfter: 8,
      code: 'SCAN_BUSY',
      message:
        'Another scan is already running. Please wait.',
      key,
    };
  }

  if (
    last &&
    now - last < COOLDOWN_MS
  ) {
    return {
      allowed: false,
      retryAfter: Math.ceil(
        (COOLDOWN_MS -
          (now - last)) /
          1000,
      ),
      code: 'SCAN_COOLDOWN',
      message:
        'Please wait before starting another scan.',
      key,
    };
  }

  if (
    last &&
    now - last >= COOLDOWN_MS
  ) {
    buckets.delete(key);
  }

  return {
    allowed: true,
    key,
  };
}

async function forward(
  request: NextRequest,
  context: {
    params: Promise<{
      path: string[];
    }>;
  },
) {
  const { path } =
    await context.params;

  const route =
    `/${path.join('/')}`;

  const target =
    `${upstream}${route}${request.nextUrl.search}`;

  let guarded = false;
  let guardKey = '';

  if (
    request.method === 'POST' &&
    isScanPath(route)
  ) {
    const check =
      guard(request);

    if (!check.allowed) {
      return new Response(
        JSON.stringify({
          error: {
            code: check.code,
            message:
              check.message,
          },
        }),
        {
          status: 429,
          headers: {
            'content-type':
              'application/json',
            'retry-after':
              String(
                check.retryAfter,
              ),
          },
        },
      );
    }

    activeScans += 1;
    guarded = true;
    guardKey = check.key;
  }

  try {
    const headers =
      new Headers();

    const contentType =
      request.headers.get(
        'content-type',
      );

    if (contentType) {
      headers.set(
        'content-type',
        contentType,
      );
    }

    if (token) {
      headers.set(
        'authorization',
        `Bearer ${token}`,
      );
    }

    const body =
      request.method === 'GET' ||
      request.method === 'HEAD'
        ? undefined
        : await request.text();

    const response =
      await fetch(
        target,
        {
          method:
            request.method,
          headers,
          body,
          cache: 'no-store',
          signal:
            request.signal,
        },
      );

    if (
      guarded &&
      response.ok &&
      !request.signal.aborted
    ) {
      buckets.set(
        guardKey,
        Date.now(),
      );
    }

    return new Response(
      response.body,
      {
        status:
          response.status,
        headers: {
          'content-type':
            response.headers.get(
              'content-type',
            ) ||
            'application/json',
          ...(response.headers.get(
            'retry-after',
          )
            ? {
                'retry-after':
                  response.headers.get(
                    'retry-after',
                  )!,
              }
            : {}),
        },
      },
    );
  } finally {
    if (guarded) {
      activeScans =
        Math.max(
          0,
          activeScans - 1,
        );
    }

    if (
      request.signal.aborted &&
      guardKey
    ) {
      buckets.delete(
        guardKey,
      );
    }
  }
}

export const GET = forward;
export const POST = forward;
export const OPTIONS =
  async () =>
    new Response(
      null,
      { status: 204 },
    );
