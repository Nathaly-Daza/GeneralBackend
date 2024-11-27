<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class PruneExpiredTokens extends Command
{
    protected $signature = 'tokens:prune';
    protected $description = 'Elimina los tokens no utilizados en las últimas 24 horas';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        // Suponiendo que tu tabla de tokens se llama "tokens"
        $expirationTime = Carbon::now()->subHours(24);
        DB::table('personal_access_tokens')
            ->where('last_used_at', '<', $expirationTime)
            ->orWhereNull('last_used_at')
            ->delete();

        $this->info('Tokens no utilizados en las últimas 24 horas han sido eliminados.');
    }
}
