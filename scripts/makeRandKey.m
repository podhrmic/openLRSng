%
% Generate a random permament key K_p
% Copy-paste the output of the script into your sketch
% and replace the existing K_p
%
clear all;
close all;
clc;

LENGTH = 32;
key = zeros(1,LENGTH)';

cnt = 1;
str = 'cont uint8_t key[] PROGMEM = {';
for k=1:LENGTH
    key(k) = randi(255);
    str = [str, num2str(key(k)), ', '];
    if (cnt==8)
        str = [str, 13, '                             ']
        cnt=0;
    end
    cnt=cnt+1;
end
str = [str(1:end-2), '  };']

