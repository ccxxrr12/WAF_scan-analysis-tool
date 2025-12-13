import type { HookFetchPlugin } from 'hook-fetch';
import { ElMessage } from 'element-plus';
import hookFetch from 'hook-fetch';
import { sseTextDecoderPlugin } from 'hook-fetch/plugins';
import router from '@/routers';
import { useUserStore } from '@/stores';

interface BaseResponse {
  code: number;
  data: never;
  msg: string;
  rows: never;
}

export const request = hookFetch.create<BaseResponse, 'data' | 'rows'>({
  baseURL: import.meta.env.VITE_API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  plugins: [sseTextDecoderPlugin({ json: true, prefix: 'data:' })],
});

function wafResponsePlugin(): HookFetchPlugin<BaseResponse> {
  return {
    name: 'waf-response',
    beforeRequest: async (config) => {
      // Remove authorization header since we don't use JWT authentication
      config.headers = new Headers(config.headers);
      config.headers.delete('authorization');
      return config;
    },
    async afterResponse(response) {
      // Parse JSON response first
      let parsedResult;
      try {
        if (response.result instanceof Response) {
          parsedResult = await response.result.json();
        } else {
          parsedResult = response.result;
        }
      } catch (error) {
        console.error('Failed to parse response:', error);
        ElMessage.error('Response parsing error');
        return Promise.reject(response);
      }

      // Handle WAF API response format (success boolean instead of code)
      if (parsedResult?.success === true) {
        // Transform WAF response to match expected format
        const transformedResult = {
          ...parsedResult,
          code: 200,
          msg: 'success',
        };
        return {
          ...response,
          result: transformedResult,
        };
      } else if (parsedResult?.success === false) {
        // Transform error response to match expected format
        const transformedResult = {
          ...parsedResult,
          code: 500,
          msg: parsedResult.error || 'error',
        };
        ElMessage.error(transformedResult.msg);
        return Promise.reject({
          ...response,
          result: transformedResult,
        });
      }
      // Fallback for other responses
      if (parsedResult?.code === 200) {
        return response;
      }
      ElMessage.error(parsedResult?.msg || 'Unknown error');
      return Promise.reject(response);
    },
  };
}

request.use(wafResponsePlugin());

export const post = request.post;

export const get = request.get;

export const put = request.put;

export const del = request.delete;

export default request;
