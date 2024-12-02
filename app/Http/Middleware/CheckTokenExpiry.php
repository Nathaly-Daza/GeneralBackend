<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class CheckTokenExpiry
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['message' => 'Token not provided'], 401);
        }

        $tokenHash = hash('sha256', $token);
        $personalAccessToken = DB::table('personal_access_tokens')->where('token', $tokenHash)->first();

        if (!$personalAccessToken || ($personalAccessToken->expires_at && now()->greaterThan($personalAccessToken->expires_at))) {
            return response()->json(['message' => 'Token expired'], 401);
        }

        return $next($request);
    }
}
