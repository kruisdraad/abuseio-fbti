while true; do date; grep -q 'not' <<< `php artisan threatex:subscriptions` && php artisan threatex:subscribe; sleep 5; done
