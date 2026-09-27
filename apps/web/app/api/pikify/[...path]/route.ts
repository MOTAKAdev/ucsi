import { NextRequest } from 'next/server';

const upstream = process.env.UCSI_INTERNAL_API || 'http://localhost:8080';
const token = process.env.UCSI_API_TOKEN || '';

async function forward(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  const { path } = await context.params;
  const target = `${upstream}/${path.join('/')}${request.nextUrl.search}`;
  const headers = new Headers();
  const contentType = request.headers.get('content-type');
  if (contentType) headers.set('content-type', contentType);
  if (token) headers.set('authorization', `Bearer ${token}`);
  const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
  const res = await fetch(target, {method:request.method,headers,body,cache:'no-store'});
  return new Response(res.body, {status:res.status, headers:{'content-type':res.headers.get('content-type') || 'application/json'}});
}

export const GET = forward;
export const POST = forward;
export const OPTIONS = async () => new Response(null,{status:204});
