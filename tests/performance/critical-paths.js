import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  thresholds: {
    // CRITICAL: Fail if 99% of requests take longer than 100ms
    http_req_duration: ['p(99)<100'], 
    // Ensure availability target
    http_req_failed: ['rate<0.01'], 
  },
  stages: [
    { duration: '1m', target: 50 }, // Ramp up to 50 users
    { duration: '3m', target: 50 }, // Stay at 50 users
    { duration: '1m', target: 0 },  // Ramp down
  ],
};

export default function () {
  const params = {
    headers: { 'Content-Type': 'application/json' },
  };

  const responses = http.batch([
    ['GET', `${__ENV.API_URL}/v1/status`, null, params],
    ['GET', `${__ENV.API_URL}/v1/node/verify`, null, params],
  ]);

  check(responses[0], { 'status is 200': (r) => r.status === 200 });
  sleep(1);
}
