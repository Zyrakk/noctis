-- Remove junk discovered sources: social media, URL shorteners, documentation
-- sites, fuzzing templates, truncated IPs, and private addresses.
DELETE FROM sources WHERE status = 'discovered' AND (
    identifier LIKE '%lnkd.in%' OR
    identifier LIKE '%youtube.com%' OR
    identifier LIKE '%youtu.be%' OR
    identifier LIKE '%google.com%' OR
    identifier LIKE '%linkedin.com%' OR
    identifier LIKE '%twitter.com%' OR
    identifier LIKE '%x.com/%' OR
    identifier LIKE '%discord.gg%' OR
    identifier LIKE '%mega.nz%' OR
    identifier LIKE '%boosty.to%' OR
    identifier LIKE '%skillbox.ru%' OR
    identifier LIKE '%habr.com%' OR
    identifier LIKE '%medium.com%' OR
    identifier LIKE '%yandex.com%' OR
    identifier LIKE '%localhost%' OR
    identifier LIKE '%127.0.0.1%' OR
    identifier LIKE '%w3.org%' OR
    identifier LIKE '%schemas.xmlsoap%' OR
    identifier LIKE '%microsoft.com%' OR
    identifier LIKE '%FUZZ%' OR
    identifier LIKE '%target.ru%' OR
    identifier LIKE '%10.0.40.64%' OR
    identifier ~ '^https?://[0-9]+\.[0-9]+\.[0-9]+$'
);
