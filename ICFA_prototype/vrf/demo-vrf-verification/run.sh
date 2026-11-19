PRV_PATH="../../prv/TRACES"
CFLOG_PATH="../cflogs/Evaluation_Data/ICFA" 

#APPS ultra, temp, CRC32, dijkstra, duff, geiger, gps, hamming,mouse, prime, search,
APP=$1

input_file="${PRV_PATH}/NonSecure/Debug/TRACES_NonSecure.list"
cflog_file="${CFLOG_PATH}/${APP}/0.cflog"
input_elf="${PRV_PATH}/NonSecure/Debug/TRACES_NonSecure.elf"

OBJDUMP=arm-none-eabi-objdump
stack="_estack"

echo "Getting .word's from the binary"
grep "word" ${input_file} > .words.tmp
awk {'print $1, $2'} .words.tmp > .words.tmp2
sed 's/:/,/g' .words.tmp2 > ./objs/.words
rm .words.tmp .words.tmp2
sed -i '/.word/d' ./objs/.words #remove any mess caused by listing file

echo "Input file: " ${input_file}
echo "Input ELF: " ${input_elf}

echo "trying to get init stack pointer val..."
${OBJDUMP} -dt ${input_elf} | grep ${stack} | awk '{print $1}' > ./objs/.sp
echo "done"
echo " "

echo "trying to get initial values for data via severral objdump calls..."
${OBJDUMP} -t ${input_elf} | grep "O \.data" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.data.objs
${OBJDUMP} -t ${input_elf} | grep "O \.bss" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.bss.objs
${OBJDUMP} -s -j .data ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.data
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $1}' > ./objs/.rodata.start
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.rodata
echo "done"
echo " "

echo "running ICFA verifier..."
python3 verify-data-log.py --asmfile ${input_file} --cfgfile ./objs/cfg.bin --cflogfile ${cflog_file}