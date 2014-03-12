use inc::Module::Install;

all_from 'lib/Net/DNS/Lite.pm';
readme_from 'lib/Net/DNS/Lite.pm';

requires 'List::MoreUtils' => 0;

test_requires 'Test::More' => 0.88;
test_requires 'Test::Requires';

repository 'https://github.com/kazuho/p5-Net-DNS-Lite';

WriteAll;
