import http from 'k6/http';
import { check, sleep } from 'k6';

// Load Test Baseline - /register endpoint
// Calibrated for a 100% success rate under local CPU constraints (2 VUs)
export const options = {
  stages: [
    { duration: '20s', target: 2 }, // Ramp-up to 2 Virtual Users
    { duration: '40s', target: 2 }, // Steady state at 2 VUs
    { duration: '10s', target: 0 }, // Ramp-down to 0 VUs
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'], // 95% of requests must complete under 3s
    http_req_failed: ['rate<0.01'],    // Error rate must remain below 1%
  },
};

export default function () {
  const url = 'http://127.0.0.1:8000/register';

  // Dynamic credentials per iteration to avoid database UNIQUE constraint collisions
  const uniqueId = `${__VU}_${__ITER}_${Date.now()}`;
  const payload = JSON.stringify({
    name: `User Test ${uniqueId}`,
    email: `user_${uniqueId}@example.com`,
    password: 'Secure-Password-Test-Load',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'k6-load-test',
    },
  };

  const res = http.post(url, payload, params);

  check(res, {
    'status is 201 (Created)': (r) => r.status === 201,
    'returns accessToken': (r) => r.body.includes('accessToken'),
  });

  sleep(1);
}