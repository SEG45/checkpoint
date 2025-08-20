#!/bin/sh
################################################################
# Check Point Script de Coleta V3
###############################################################
# Compugraf 
################################################################
main() {

	CG_coleta_version="3.0.0 - 08/08/2023"
	DIR=/var/log/`hostname`
	database="$CPDIR/log/cpview_services/cpview_services.dat"
	DirLocal=$(pwd)
	ISGW=`$CPDIR/bin/cpprod_util FwIsFirewallModule 2>/dev/null`

	clear
	echo
	echo
	echo "**************************"
	echo "SCRIPT DE COLETA COMPUGRAF"
	echo "Versao: $CG_coleta_version"
	echo "**************************"

	if [ -e $DIR ]; then
	   rm -r $DIR
    fi

	writeLog "Inicio da coleta" 
	writeLog "lock database" 
	clish -c 'lock database override' 2>&1 | writeLog

	mkdir -p $DIR
	mkdir -p $DIR/arquivosSO
	mkdir -p $DIR/arquivosSO/var/ace
	mkdir -p $DIR/arquivosSO/var/sa

	mkdir -p $DIR/HCP
	mkdir -p $DIR/Graficos
	
	mkdir -p $DIR/CPinfo
	mkdir -p $DIR/Validacao

	writeLog "Informacoes de SO"
	func_os_info
	writeLog "Informacoes de Upgrade"
	func_upgrade_info
	writeLog "Copiando arquivos de configuracoes"
	func_fw_files
	echo " "
	echo -n " 4. Gerando Graficos..."
	writeLog "Gerando grafico de spike"
    func_grafico_spike
    echo -n "."
	writeLog "Gerando grafico de CPU"
    func_grafico_cpu
    echo -n "."
	writeLog "Gerando grafico de memoria"
    func_grafico_memoria
    echo -n "."
	writeLog "Gerando grafico de interfaces"
    func_grafico_interface
    echo -n "."
    echo  -n "Ok"	
	echo 
	
	echo -n " 5. Gerando arquivos para validacao..."
	writeLog "Gerando arquivos para validacao"
	gera_config
    echo  -n "Ok"	
	echo 
	
	writeLog "Gerando HCP"
	echo -n " 6. Gerando HCP (pode levar alguns minutos)..."
	hcp -r all --include-topology yes >> $DIR/HCP/HCP_Resultado_`hostname`.txt
	cp /var/log/hcp/last/hcp*.* $DIR/HCP
    echo -n "Ok"
	echo 
	
	
	#cpinfo -d -D -i -z -o /var/log/cpinfo-$(hostname)-$(date +%d-%m-%Y)


	if [[ $ISGW -eq "0" ]]; then
	#Se for Manager
		
		echo -n " 7. Gerando CPinfo com Migrate (pode levar varios minutos)......"
		writeLog "Gerando CPinfo e Migrate"
		mkdir -p $DIR/Migrate	
		cd $DIR/Migrate
		
		cpinfo -d -D -i -z -o $DIR/CPinfo/CPinfo_`hostname`  >> $DirLocal/log.coleta 2>> $DirLocal/log.coleta
		echo -n "Ok"

		cd $DirLocal

	else
		#Se for Gateway
		writeLog "Gerando CPinfo"
	    echo -n " 7. Gerando CPinfo (pode levar alguns minutos)......"
		cpinfo -d -D -i -z -o $DIR/CPinfo/CPinfo_`hostname`  >> $DirLocal/log.coleta 2>> $DirLocal/log.coleta
		echo -n "Ok"

	fi
	
	writeLog "Comprimindo arquivos"
	echo " "
	echo -n " 8. Comprimindo arquivos [ColetaCG_`hostname`.tar]..."
	
	
	tar chofP ColetaCG_`hostname`.tar $DIR 

	echo  -n "Ok"

	#rm -r $DIR/HCP
	rm -r $DIR/Graficos
	#if [[ $ISGW -eq "0" ]]; then rm -r $DIR/Migrate; fi 
	#rm -r $DIR/CPinfo
	
	echo 
	echo 
	echo "******************************************************************************"
	echo " O arquivo `pwd`/ColetaCG_`hostname`.tar Foi criado com sucesso!!!"
	echo " Favor copiar o(s) arquivo(s) para o SFTP da Compugraf"
	echo "*******************************************************************************"
	echo
	echo " (Favor remover o(s) arquivo(s) gerado(s) depois de copia-lo(s)!!!)"
	echo 
	echo "Script de coleta efetuado com sucesso."
	
	writeLog "Fim da coleta."


	echo
	read -p "Deseja enviar o arquivo gerado para o servidor suporte.cg-one.com? (s/n): " resposta

	if [ "$resposta" = "s" ] || [ "$resposta" = "S" ]; then
		ARQ="ColetaCG_`hostname`.tar"

		if [ ! -f "$ARQ" ]; then
			echo "Arquivo $ARQ não encontrado no diretório atual: `pwd`"
			writeLog "Envio abortado: arquivo $ARQ não encontrado"
		else
			read -p "Informe o usuário do SFTP: " sftp_user
			read -s -p "Informe a senha do SFTP: " sftp_pass
			echo

			TMPFILE=$(mktemp)
			# Primeiro vai para a pasta /upload
			echo "cd /upload" > "$TMPFILE"
			echo "put $ARQ" >> "$TMPFILE"
			echo "bye" >> "$TMPFILE"

			echo "Enviando $ARQ para suporte.cg-one.com:/upload ..."

			if command -v sshpass >/dev/null 2>&1; then
				sshpass -p "$sftp_pass" sftp -oBatchMode=no -oStrictHostKeyChecking=no \
					"$sftp_user@suporte.cg-one.com" < "$TMPFILE"
				sftp_rc=$?

				if [ $sftp_rc -eq 0 ]; then
					echo "Arquivo enviado com sucesso para suporte.cg-one.com:/upload!"
					writeLog "Arquivo $ARQ enviado com sucesso para suporte.cg-one.com:/upload"
				else
					echo "Falha ao enviar o arquivo via SFTP (rc=$sftp_rc)."
					writeLog "Falha no envio via SFTP (rc=$sftp_rc)"
				fi
			else
				echo "sshpass não está instalado. Tentando modo interativo..."
				writeLog "sshpass ausente; tentando envio interativo"
				sftp "$sftp_user@suporte.com.br" < "$TMPFILE"
			fi

			rm -f "$TMPFILE"
		fi
	fi




}
#######################################
# Write a given message
# ARGS:
#   String to print
# RETURN:
#
#######################################
writeLog()
{
  echo -e "$(date +%F\ %T) - "$@ >> $DirLocal/log.coleta
}
writeError()
{
  writeLog "${RED}$@${DEFAULT}"
}
writeWarn()
{
  writeLog "${YELLOW}$@${DEFAULT}"
}


func_os_info() {
		Comandos="hostname 
			cphaprob stat
			uname -a
			fw ver -k
			cplic print -x
			df -kh
			free -m
			cpstat -f cpu os
			fw -d ctl affinity -corelicnum
			fw ctl pstat
			ifconfig -a
			cpstat os -f all
			cpstat fw -f all
			cpstat vpn -f all
			cpstat ha -f all
			fw stat -i -l
			enabled_blades
			cpinfo -y all
			ps auxwww
			arp -a
			netstat -rn"
			
			
	echo "$CG_coleta_version" >> $DIR/.version.txt 
	echo " "
	echo -n " 1. Coletando informacoes do SO..."
	echo "-- Iniciando coleta em `date +%d/%m/%Y` - `date +%H:%M`" > $DIR/soinfo.txt 2> $DIR/soinfo.txt

	writeLog "show asset all"
	echo "********** show asset all :" >> $DIR/soinfo.txt 2>>$DIR/soinfo.txt	
	clish -c "show asset all " >> $DIR/soinfo.txt 2>>$DIR/soinfo.txt


	echo "$Comandos" | while read COMAND; do
		writeLog "$COMAND"
		echo " "		     >> $DIR/soinfo.txt 2>>$DIR/soinfo.txt
		echo "********** $COMAND :" >> $DIR/soinfo.txt 2>>$DIR/soinfo.txt
		$COMAND >> $DIR/soinfo.txt 2>>$DIR/soinfo.txt
		echo -n "."
	done

	echo "Ok"
}

func_upgrade_info() {
	echo -n " 2. Coletando informacoes para Migracao..."

	echo "-- Iniciando coleta em `date +%d/%m/%Y` - `date +%H:%M`" > $DIR/upgradeinfo.txt 2> $DIR/upgradeinfo.txt 
	echo " "		     >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt
	
	Comandos='cpmq get -v 
			mq_mng -o
			dynamic_objects -l
			fw ctl multik stat
			fw ctl affinity -l -v
			fw ctl multik dynamic_dispatching get_mode
			cpprod_util FwIsUsermode
			dynamic_split -p
			cp_log_export show
			fw ctl fast_accel show_table
			fw ctl fast_accel export_conf'
			

	echo "$Comandos" | while read COMAND; do
		writeLog "$COMAND"
		echo "********** $COMAND :" >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt
		$COMAND >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt
		echo " " >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt
		echo -n "."
	done


	Comandos='lom ip-address 
			cloning-group state
			cloning-group members
			cloning-group mode
			cloning-group name
			cloning-group status'

	echo "$Comandos" | while read COMAND; do
		writeLog "$COMAND"
		echo "********** $COMAND :" >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt	
		clish -c "show ${COMAND} " >> $DIR/upgradeinfo.txt 2>>$DIR/upgradeinfo.txt		
		echo -n "."		
	done
	writeLog "show configuration"
	clish -c "show configuration" >> $DIR/ShowConfiguration 
	echo -n "."
	echo -n "Ok"
}



func_fw_files() {
	echo " "
	echo -n " 3. Copiando arquivos para migracao..."

	Arquivos='$FWDIR/bin/cpisp_update /etc/rc.local $FWDIR/conf/masters $FWDIR/conf/local.scv $FWDIR/conf/snmp.C /etc/snmp/snmpd.conf $FWDIR/conf/trac_client_1.ttm 
				$FWDIR/boot/modules/fwkern.conf $FWDIR/boot/modules/vpnkern.conf $PPKDIR/boot/modules/simkern.conf $PPKDIR/boot/modules/sim_aff.conf $FWDIR/conf/fwaffinity.conf 
				$FWDIR/conf/fwauthd.conf $FWDIR/conf/local.arp $FWDIR/conf/discntd.if $FWDIR/conf/cpha_bond_ls_config.conf $FWDIR/conf/resctrl $FWDIR/conf/vsaffinity_exception.conf
				$FWDIR/database/qos_policy.C $FWDIR/conf/fw_fast_accel_export_configuration.conf'

		
	for F in `echo $Arquivos`; do
		ARQ=`eval echo $F`
		if [ -e $ARQ ]; then
			writeLog "$F"
			cp $ARQ $DIR/arquivosSO		
			echo -n "."
			echo -n "$F " >> $DIR/Validacao/arquivos
		fi
		
	done
 
	if [ -e "/var/ace/sdconf.rec" ]; then
		writeLog "/var/ace/sdconf.rec"
		cp /var/ace/sdconf.rec $DIR/arquivosSO/var/ace
		echo -n "."
    fi
	
	if [ -e "/var/ace/sdopts.rec" ]; then
		writeLog "/var/ace/sdopts.rec"
		cp /var/ace/sdopts.rec $DIR/arquivosSO/var/ace
		echo -n "."
    fi
	
	 
	if [ -e "$EXPORTERDIR/targets" ]; then
		writeLog "$EXPORTERDIR/targets"
		mkdir -p $DIR/log_exporter/targets
		cp -r $EXPORTERDIR/targets/ $DIR/log_exporter
		echo -n "."
	fi

	if [ -e "/var/log/sa" ]; then
		writeLog "/var/log/sa"
		cp -r /var/log/sa $DIR/arquivosSO/var/sa
		echo -n "."
	fi


	echo -n "Ok"
}

gera_config(){

	CONFIGS='aaa aggregate allowed-client arp as backup-scheduled bgp bonding bootp bridging clienv cluster command core-dump 
			cron dhcp-client dhcp-server dns domainname expert-password format gre group 
			host hostname igmp inbound-route-filter installer interface interface-name ip-conflicts-monitor 
			ip-reachability-detection iphelper ipsec-routing ipv6 ipv6-state kernel-routes lcd lldp mail-notification 
			management max-path-splits mcvr mdps message nat-pool neighbor net-access netflow ntp ospf password-controls 
			pbr pbrroute pim ping pppoe prefix-list prefix-tree protocol-rank proxy rba rdisc rip route-redistribution routedsyslog 
			routemap routemaps router-id router-options snapshot-scheduled snmp ssh ssl static-mroute static-route 
			syslog timezone trace tracefile user vpnt vrrp vxlan web'

	echo -n "."
	for F in `echo $CONFIGS`; do
		PARAM=`eval echo $F`	
		writeLog "${PARAM}"
		clish -c "show configuration ${PARAM}" >> $DIR/Validacao/$PARAM.old			
	done
	echo -n "."
	writeLog "Gera Tabela"
	gera_tabela
	echo -n "."

}


gera_tabela(){
	if [[ ! -f /etc/cp-release ]]; then echo "Unsupported OS"; exit 1; fi
	if [[ -n `grep Embed /etc/cp-release` ]]; then echo "Unsupported OS"; exit 1; fi
	OS=`cat /etc/cp-release|cut -c 13-|sed 's/^ *//g'|sed 's/\s*$//g'`;
	if [[ -e /etc/profile.d/CP.sh ]]; then source /etc/profile.d/CP.sh; else echo "Unsupported Environment"; exit 1; fi
	if [[ -e /etc/profile.d/vsenv.sh ]]; then source /etc/profile.d/vsenv.sh; fi
	bind '"\e[0n": self-insert' 2>/dev/null;

	i=0; j=1; k=1; l=1; m=1; n=1; o=1; p=1; r=1; s=1; t=1; u=1; v=1; w=1; x=1
	MGMT=`if [ -f $FWDIR/conf/masters ]; then cat $FWDIR/conf/masters|awk 'NR>1 && NR<3 { print $1 }'; else echo localhost; fi`; echo -n .
	MGIP=`if [ -f $CPDIR/registry/HKLM_registry.data ]; then cat $CPDIR/registry/HKLM_registry.data|grep ICAip|awk '{print $2}'; fi`; echo -n .
	RUN=''; ADD=''; FIN=''; LICS=''; ABEXP=''; AVEXP=''; ISGW=0; ISUPD=0; MHOTYPE=''; NOW=`date +%s`; TIMESTAMP=`date +'%Y/%m/%d %H:%M' 2>/dev/null`

	HOST=`hostname`; HOSTIP=`grep ' '$HOST$ /etc/hosts | cut -f1 -d' '`
	THIS=$(dirname `readlink -f $0`)`echo -n "/"; basename $0`
	TYPE=`cpstat os | grep "Appliance Name" | tr -s ' ' | cut -c 17-`; if [[ -z $TYPE ]]; then TYPE="Open Server"; fi;
	if [[ -e /etc/cloud-version ]]; then TYPE=`cat /etc/cloud-version | grep platform | cut -f2 -d' '`; if [[ ${#TYPE} -ge 4 ]]; then TYPE=`tr '[:lower:]' '[:upper:]' <<< ${TYPE:0:1}`${TYPE:1}; else TYPE=`echo "$TYPE" | tr '[:lower:]' '[:upper:]'`; fi; TYPE+=' Cloud'; fi;
	echo -n .
	case `echo ${TYPE:0:5}` in Check|Maest) SERIAL=`cpstat os|grep "Appliance SN"|awk '{print $NF}'`; echo -n .; MAC=`cplic print|tr ' ' '\n'|grep CK-|tail -1|tr '-' ':'|sed 's/CK://'`; PSU=`clish -c 'show sysenv all'|grep Power|awk '{print $3": "$4}'|sed 's/#//'|tr '\n' ' '|sed 's/Up /Up  /'`;; *) ;; esac
	if [[ "$TYPE" == *'Orchestrator'* ]]; then MAC=`dmidecode -t1|grep UUID|awk '{print $NF}' FS=-|sed 's/../&:/g; s/:$//'`; fi
	if [[ "$SERIAL" == '' ]]; then SERIAL="N/A"; fi
	if [[ `service snmpd status` == *'running'* ]]; then if [[ `grep snmp:version /config/active|awk '{print $NF}'` == 'v3-Only' ]]; then SNMP="v3 Only"; else SNMP="${RED}${TXT}Insecure${NORM}"; fi; fi
	RAID=`raid_diagnostic | grep RaidLevel | awk '{print $6}' | cut -c 7-`; if [[ -z $RAID ]]; then RAID=`raidconfig status | grep -A1 State | tail -1 | sed 's@.* @@'`; if [[ -z $RAID ]]; then RAID="-"; fi; else RAID="${RAID:0:1}$(tr '[:upper:]' '[:lower:]' <<< ${RAID:1})"; fi; echo -n .
	if [[ "$RAID" != "Optimal" ]] && [[ "$RAID" != "-" ]]; then RAID="${RED}${TXT}${RAID}"; fi
	if     [[ `echo $MDSDIR | grep mds` ]]; then SYSTEM="Multi-Domain Server (MDS)"
	elif [[ `$CPDIR/bin/cpprod_util FwIsVSX 2>/dev/null` == *'1'* ]]; then SYSTEM="Virtual System Extension (VSX)"
	elif [[ `$CPDIR/bin/cpprod_util FwIsStandAlone 2>/dev/null` == *'1'* ]]; then SYSTEM="Standalone Firewall & Management"
	elif [[ `cpstat -f all ha 2>/dev/null | grep "HA started:" | tr -s ' '` == 'HA started: yes' ]]; then MODE=`cpstat -f all ha | grep "Working mode:" | tr -s ' ' | cut -c 15,20`; STAT=`cpstat -f all ha | grep "HA state:" | tr -s ' ' | cut -c 11-`; STAT="$(tr '[:lower:]' '[:upper:]' <<< ${STAT:0:1})${STAT:1}"; if [[ "$TYPE" == *'Maestro'* ]]; then SYSTEM="Security Group > ${STAT}"; else SYSTEM="Firewall Cluster Node (${MODE}) > ${STAT}"; fi; SYNC=`cphaprob -a if|grep sync|sed '/non/d'|wc -l`; if [[ $SYNC -ne "1" ]]; then SYNC="${RED}${TXT}${SYNC} sync interfaces found (sk92804) "; fi
	elif [[ `$CPDIR/bin/cpprod_util FwIsFirewallModule 2>/dev/null` == *'1'* ]]; then SYSTEM="Firewall Gateway"
	elif [[ `cpwd_admin list | grep EPM | cut -c 1-3` == 'EPM' ]]; then SYSTEM="Endpoint Management"
	elif [[ `$CPDIR/bin/cpprod_util FwIsFirewallMgmt 2>/dev/null` == *'1'* ]] && [[ `cpwd_admin list | grep -o CPSEMD` == "CPSEMD" ]];  then SYSTEM="Firewall Management (with Smart Event)"
	elif [[ `$CPDIR/bin/cpprod_util FwIsFirewallMgmt 2>/dev/null` == *'1'* ]]; then SYSTEM="Firewall Management";  if [[ -e $MDS_FWDIR/conf/dbsyncStatus.C ]]; then if [[ `grep ': (' $MDS_FWDIR/conf/dbsyncStatus.C | sed '/\t\t/d' | wc -l` != "1" ]]; then SYSTEM="Firewall Management HA"; if [[ `grep Primary $CPDIR/registry/HKLM_registry.data|sed 's/[^0-9]*//g'` == *'1'* ]]; then SYSTEM+=" (Primary, "; else SYSTEM+=" (Secondary, "; fi; if [[ `cpstat mg|grep status|awk 'NF>1{print $NF}'` == *'by'* ]]; then SYSTEM+="Standby)"; else SYSTEM+="Active)"; fi; fi; fi
	elif [[ `cpwd_admin list | grep CPSEMD | cut -c 1-6` == 'CPSEMD' ]]; then SYSTEM="SmartEvent Server"
	elif [[ "$TYPE" == *'Orchestrator'* ]]; then SYSTEM="MHO"
	  if [[ `jsont -f /etc/smodb.json -g /ssm_groups_amount` == 2 ]] && [[ `jsont -f /etc/smodb.json -g /lb_amount` == 2 ]]; then MHOTYPE=" (Dual Site, Dual Orchestrator)"; fi
	  if [[ `jsont -f /etc/smodb.json -g /ssm_groups_amount` == 2 ]] && [[ `jsont -f /etc/smodb.json -g /lb_amount` == 1 ]]; then MHOTYPE=" (Dual Site, Single Orchestrator)"; fi
	  if [[ `jsont -f /etc/smodb.json -g /ssm_groups_amount` == 1 ]] && [[ `jsont -f /etc/smodb.json -g /lb_amount` == 2 ]]; then MHOTYPE=" (Single Site, Dual Orchestrator)"; fi
	  if [[ `jsont -f /etc/smodb.json -g /ssm_groups_amount` == 1 ]] && [[ `jsont -f /etc/smodb.json -g /lb_amount` == 1 ]]; then MHOTYPE=" (Single Site, Single Orchestrator)"; fi
	  ORCHSTAT=`orchd status|head -n1|awk '{print $NF}'|sed 's/.*/\u&/'`; if [[ "$ORCHSTAT" -ne "Active" ]]; then ORCHSTAT="${RED}${TXT}${ORCHSTAT}"; fi;
	  SDKSTAT=`orchd status|tail -n1|awk '{print $NF}'|sed 's/.*/\u&/'`; if [[ "$SDKSTAT" -ne "Loaded" ]]; then SDKSTAT="${RED}${TXT}${SDKSTAT}"; fi;
	else SYSTEM="N/A"
	fi
	echo -n .
	CPUMOD=`grep name /proc/cpuinfo | head -n1 | sed 's/^.*:[ \t]*//' | tr -s " "`;
	OSMODE=`uname -a | grep -c x86_64`; [ $OSMODE == 0 ] && { OSMODE=32; } || { OSMODE=64; }
	KERNEL=`uname -r | sed 's/\([0-9]\+\.[0-9]\+\)\..*/\1/'`
	DRIVER=`ls -1 /sys/class/net | grep -v ^lo | xargs -I % sh -c 'ethtool % 2>/dev/null; ethtool -i % 2>/dev/null' | grep '^driver\|Speed\|Duplex\|Settings' | grep driver | sort -u | cut -c 9- | tr '\n' ',' | sed 's/usbnet,//g' | sed s'/.$//' | sed 's/,/, /g' | sed s/be2net/\`echo "${RED}${TXT}be2net${NORM}${BOLD}"\`/ | sed s/bge/\`echo "${RED}${TXT}bge${NORM}${BOLD}"\`/ | sed s/usbnet/\`echo "${RED}${TXT}usbnet${NORM}${BOLD}"\`/ | sed s/cdc_ether/\`echo "${RED}${TXT}cdc_ether${NORM}${BOLD}"\`/ | sed s/bnx2x/\`echo "${RED}${TXT}bnx2x${NORM}${BOLD}"\`/ | sed s/bnx2,/\`echo "${RED}${TXT}bnx2${NORM}${BOLD},"\`/ | sed s/tg3/\`echo "${RED}${TXT}tg3${NORM}${BOLD}"\`/ `; echo -n .
	CPUSE=`cat /config/db/initial | grep da_build | awk '{print $NF}'`
	NTIME=`if [[ -e /usr/bin/ntpstat ]]; then ntpstat 2>/dev/null | tr -d '\n' | sed 's/.*unsynchronised.*/_/' | sed 's/.*synchronised.*/Synced/'; else echo "${RED}${TXT}ntpstat missing"; fi`; if [[ "$NTIME" == "_" ]]; then NTIME="${RED}${TXT}No sync"; elif [[ "$NTIME" == "" ]]; then NTIME="${RED}${TXT}ntpd error"; fi
	JUMBO=`cpinfo -y all 2>/dev/null|grep HF_MAIN|tail -n1|awk '{print $NF}'`; [ "$JUMBO" == '' ] && JUMBO="-"
	if [[ "$TYPE" == *'Maestro'* ]] && [[ "$SYSTEM" != "MHO" ]]; then isSMO=`fwproc fwha_global_params.conf get fwha_smo_is_mgmt_master`; if [ -z "$isSMO" ] || [ "$isSMO" == "1" ]; then HOSTIP+=" (SMO)"; fi; CLONESTAT=`grep image_clone /config/active|awk '{print $NF}'|sed 's/.*/\u&/'`; if [[ "$CLONESTAT" -ne "Off" ]]; then CLONESTAT="${RED}${TXT}${CLONESTAT}"; fi; fi
	CORE=`grep -c ^processor /proc/cpuinfo`; echo -n .
	MEMO=`free -g`; RAM=`dmidecode -t memory | grep  Size: | grep -v "No Module Installed" | awk '{sum+=$2/1024}END{print sum}'`; if [[ $RAM < `echo "$MEMO" | gawk '/Mem:/{print $2}'` ]]; then RAM=`echo "$MEMO" | gawk '/Mem:/{print $2}'`; ((RAM++)); fi
	if [[ "$MEMO" == *'available'* ]]; then FREE=`echo "$MEMO"|gawk '/Mem:/{print $7}'`; TAG="Avail"; else FREE=`echo "$MEMO"|gawk '/Mem:/{print $4}'`; TAG="Free"; fi
	SWAP=`echo "$MEMO" | gawk '/Swap:/{print $3}'`; if [[ $SWAP -eq "0" ]]; then SWAP="Swapping ${BOLD}${SWAP} GB${NORM}"; else SWAP="${RED}${TXT}${BOLD} Swapping ${SWAP} GB ${NORM}"; fi
	LOAD=`uptime | sed 's/.*://' | tr -d , | awk '{print $1}'`; echo -n .
	DUMPS=`if [ -z "$(ls -A /var/log/dump/usermode/)" ]; then echo -; else echo "${RED}${TXT}${BOLD}Present${NORM}"; fi`
	CRASH=`if [ -z "$(ls -A /var/log/crash/)" ] && [ -z "$(ls -A /var/crash/)" ]; then echo -; else echo "${RED}${TXT}${BOLD}Present${NORM}"; fi`
	nc -z -w 3 dannyjung.de 443 2>/dev/null; if [[ $? -eq 0 ]]; then UPDT=`curl_cli -fsk https://dannyjung.de/ccc | zcat 2>/dev/null`; [ $? -eq 0 ] && Update=${UPDT:21:3} || Update="$Version"; else Update="$Version"; fi
	if [[ "$Update" != "$Version" ]]; then CHKSUM=`curl_cli -fsk https://dannyjung.de/ccc-sha512 | zcat 2>/dev/null`; if [[ $? -eq 0 ]]; then if [[ `echo "$UPDT" | sha512sum | cut -d " " -f 1` != $CHKSUM ]]; then Update="$Version"; fi; else Update="$Version"; fi; fi
	[ "$Update" == "$Version" ] && unset UPDT;
	ISGW=`$CPDIR/bin/cpprod_util FwIsFirewallModule 2>/dev/null`; echo -n .
	[ $ISGW == 0 ] && { ISGW=`$CPDIR/bin/cpprod_util FwIsVSX 2>/dev/null`; }
	[ $ISGW == 1 ] && { if [[ -n "$vsname" ]] && [[ $vsname != *'unavail'* ]]; then vsenv $INSTANCE_VSID >/dev/null 2>&1; fi; }
	if [[ -n `echo $HOST|tr '-' '\n'|grep -E '^accept$|^all$|^All$|^and$|^any$|^Any$|^apr$|^Apr$|^april$|^April$|^aug$|^Aug$|^august$|^August$|^black$|^blackboxs$|^blue$|^broadcasts$|^call$|^comment$|^conn$|^date$|^day$|^debug$|^dec$|^Dec$|^december$|^December$|^deffunc$|^define$|^delete$|^delstate$|^direction$|^do$|^domains$|^drop$|^dst$|^dynamic$|^edge$|^else$|^expcall$|^expires$|^export$|^fcall$|^feb$|^Feb$|^february$|^February$|^firebrick$|^foreground$|^forest$|^format$|^fri$|^Fri$|^friday$|^Friday$|^from$|^fw1$|^FW1$|^fwline$|^fwrule$|^gateways$|^get$|^getstate$|^gold$|^gray$|^green$|^hashsize$|^hold$|^host$|^hosts$|^if$|^ifaddr$|^ifid$|^implies$|^in$|^inbound$|^instate$|^interface$|^interfaces$|^ipsecdata$|^ipsecmethods$|^is$|^jan$|^Jan$|^january$|^January$|^jul$|^Jul$|^july$|^July$|^jun$|^Jun$|^june$|^June$|^kbuf$|^keep$|^limit$|^local$|^localhost$|^log$|^log$|^log.ics$|^magenta$|^mar$|^Mar$|^march$|^March$|^may$|^May$|^mday$|^medium$|^modify$|^mon$|^Mon$|^monday$|^Monday$|^month$|^mortrap$|^navy$|^netof$|^nets$|^nexpires$|^not$|^nov$|^Nov$|^november$|^November$|^oct$|^Oct$|^october$|^October$|^or$|^orange$|^origdport$|^origdst$|^origsport$|^origsrc$|^other$|^outbound$|^packet$|^packetid$|^packetlen$|^pass$|^r_arg$|^r_call_counter$|^r_cdir$|^r_cflags$|^r_chandler$|^r_client_community$|^r_client_ifs_grp$|^r_community_left$|^r_connarg$|^r_spii_uuid4$|^r_str_dport$|^r_str_dst$|^r_str_ipp$|^r_str_sport$|^r_str_src$|^r_user$|^record$|^red$|^refresh$|^reject$|^routers$|^r_crule$|^r_ctimeout$|^r_ctype$|^r_curr_feature_id$|^r_data_offset$|^r_dtmatch$|^r_dtmflags$|^r_entry$|^r_g_offset$|^r_ipv6$|^r_mapped_ip$|^r_mflags$|^r_mhandler$|^r_mtimeout$|^r_oldcdir$|^r_pflags$|^r_profile_id$|^r_ro_client_community$|^r_ro_dst_sr$|^r_ro_server_community$|^r_ro_src_sr$|^r_scvres$|^r_server_community$|^r_server_ifs_grp$|^r_service_id$|^r_simple_hdrlen$|^r_spii_ret$|^r_spii_tcpseq$|^r_spii_uuid1$|^r_spii_uuid2$|^r_spii_uuid3$|^sat$|^Sat$|^saturday$|^Saturday$|^second$|^sep$|^Sep$|^september$|^September$|^set$|^setstate$|^skipme$|^skippeer$|^sr$|^src$|^static$|^sun$|^Sun$|^sunday$|^Sunday$|^switchs$|^sync$|^targets$|^thu$|^Thu$|^thursday$|^Thursday$|^to$|^tod$|^tue$|^Tue$|^tuesday$|^Tuesday$|^ufp$|^vanish$|^vars$|^wasskipped$|^wed$|^Wed$|^wednesday$|^Wednesday$|^while$|^xlatedport$|^xlatedst$|^xlatemethod$|^xlatesport$|^xlatesrc$|^xor$|^year$|^zero$|^zero_ip$|^CPM$|^Global$|^Web$|^mon$|^Mon$|^monday$|^Monday$|^tue$|^Tue$|^tuesday$|^Tuesday$|^wed$|^Wed$|^wednesday$|^Wednesday$|^thu$|^Thu$|^thursday$|^Thursday$|^fri$|^Fri$|^friday$|^Friday$|^sat$|^Sat$|^saturday$|^Saturday$|^sun$|^Sun$|^sunday$|^Sunday$|^jan$|^Jan$|^january$|^January$|^feb$|^Feb$|^february$|^February$|^mar$|^Mar$|^march$|^March$|^apr$|^Apr$|^april$|^April$|^may$|^May$|^jun$|^Jun$|^june$|^June$|^jul$|^Jul$|^july$|^July$|^aug$|^Aug$|^august$|^August$|^sep$|^Sep$|^september$|^September$|^oct$|^Oct$|^october$|^October$|^nov$|^Nov$|^november$|^November$|^dec$|^Dec$|^december$|^December$|^date$|^day$|^month$|^year$|^black$|^blue$|^cyan$|^dark$|^firebrick$|^foreground$|^forest$|^gold$|^gray$|^green$|^magenta$|^medium$|^navy$|^orange$|^red$|^sienna$|^yellow$|^Account$|^Alert$|^Auth$|^AuthAlert$|^Duplicate$|^gateways$|^host$|^Long$|^Mail$|^netobj$|^resourceobj$|^routers$|^servers$|^servobj$|^Short$|^SnmpTrap$|^spoof$|^spoofalert$|^targets$|^tracks$|^ufp$|^UserDefined$|^dynobj_list$|^full_service_list$|^ip_list$|^rulenum_list$|^service_list$|^target_list$|^tcpt_list$|^valid_addrs_list$|^ipv6$|^block$|^cp_mgmt$|^art$|^dns_atma$|^wmp_sami$|^rtf$|^sctp$|^rpc$|^diameter$'` ]]; then FLAG=1; fi
	if [[ -n `echo $HOST|grep -E '^firewall-1$|^fw1$|^FW1$|^fw-1$|^mail$|^smtp$'` ]]; then FLAG=1; fi
	if [[ -e /var/log/CPbackup/backups/.last_backup_status ]]; then BCKP=`cat /var/log/CPbackup/backups/.last_backup_status|tr -d '.'`; if ((($NOW-`date -r /var/log/CPbackup/backups/.last_backup_status +%s 2>/dev/null`) > 2592000 )); then BCKP="${RED}${TXT}Last backup too old"; elif [[ -z `grep ucce /var/log/CPbackup/backups/.last_backup_status` ]]; then BCKP="${RED}${TXT}Failure creating backups"; fi; else BCKP="${RED}${TXT}No Backups configured"; fi


	if [[ $ISGW -eq "1" ]]; then
	  if [ -n $FWDIR/conf/vsname ] || [[ $INSTANCE_VSID == '0' ]]; then LIC=`fw ctl affinity -l -r | grep "CPU " | awk '{print $3}' | sed '/^\s*$/d' | wc -l`; echo -n .; case `echo ${TYPE:0:5}` in Check) ;; *) LICS=`fw ctl get int fwlic_num_of_allowed_cores | sed 's/[^0-9]*//g'`; if [[ $LICS -lt $CORE ]]; then LICS="${RED}${TXT}${BOLD} $LICS licensed ${NORM}"; else LICS=''; fi ;; esac; fi; if [[ -n "$vsname" ]] && [[ $vsname != *'unavail'* ]]; then HOST=`echo $vsname' (ID: '$INSTANCE_VSID')'`; if [[ $INSTANCE_VSID == '0' ]]; then VSTYPE=$TYPE; else VSTYPE=`cphaprob -vs $INSTANCE_VSID stat | tr -d '.\t\n' | rev | awk '{NF=2}1' | rev`; if [[ $VSTYPE != *"Switch"* ]] && [[ $VSTYPE != *"Router"* ]]; then VSTYPE='Virtual System'; fi; fi; fi; if [[ `fw ctl get int fw_allow_out_of_state_tcp` -eq 0 ]]; then STATE="Stateful"; else STATE="${RED}${TXT}No Stateful Inspection"; fi; if [[ `fw ctl multik stat 2>/dev/null | wc -l` == "0" ]]; then CXL="${RED}${TXT}${BOLD}Off${NORM}"; else CXL="On"; fi; echo -n .; case `echo ${OS#*R*}` in 77.30|80.10) SXL=`fwaccel stat | grep "Accelerator Status :" | cut -c 22- | sed 's/on/On/g' | sed 's/off/Off/g'`;; *) SXL=`fwaccel stat | sed -n 4p | tr '|' ' ' | awk '{print $3}' | sed 's/enabled/On/g' | sed 's/disabled/Off/g'`; esac; if [[ $SXL == "Off" ]]; then SXL="${RED}${TXT}${BOLD}Off${NORM}"; fi; echo -n .; if [[ -e /proc/smt_status ]]; then SMT=`cat /proc/smt_status | sed 's/Soft Disable/Off/g' | sed 's/Enable/On/g' | sed 's/Unsupported/-/g'`; elif [[ -e /sys/devices/system/cpu/smt/active ]]; then SMT=`cat /sys/devices/system/cpu/smt/active | sed 's/1/On/g' | sed 's/0/Off/g'`; else SMT='-'; fi; echo -n .; CPMQ=`cpmq get -a 2>/dev/null`; MQON=`echo "$CPMQ" | grep -c "\[On\]"`; MQIF=`echo "$CPMQ" | grep -c "\["`; echo -n .; case $MQIF in 0) CPMQ="-";; *) CPMQ="$MQON/$MQIF";; esac; case `echo ${OS#*R*}` in 77.30) DYN=`fw ctl multik get_mode | cut -c 17-`;; *) DYN=`fw ctl multik dynamic_dispatching get_mode | cut -c 17-`;; esac; case `echo ${OS#*R*}` in 80.40|81*) if [[ `dynamic_split -p 2>/dev/null | grep off | wc -l` != "0" ]]; then SPLIT="Off"; else SPLIT="On"; fi;; esac;
	  case `echo ${OS#*R*}` in 77.30) IPSUPD=`if [ -f $FWDIR/state/local/FW1/local.set ]; then grep -A2 "sd_last_update_time" $FWDIR/state/local/FW1/local.set | date -d @$(tr -dc '[0-9]') +"%b %d %Y @%H:%M" | tr '@' '\`'; fi`; IPSUPD2=`echo $IPSUPD | tr '\`' '@'`; if [ -f $FWDIR/state/local/AMW/local.IPS.set ]; then if ((($NOW-`grep -A2 "sd_last_update_time" $FWDIR/state/local/AMW/local.IPS.set | tr -dc '[0-9]'`) > 604800 )); then IPSUPD="${RED}${TXT}${IPSUPD}"; fi; fi ;; *) IPSUPD=`if [ -f $FWDIR/state/local/AMW/local.IPS.set ]; then grep -A2 "sd_last_update_time" $FWDIR/state/local/AMW/local.IPS.set | date -d @$(tr -dc '[0-9]') +"%b %d %Y @%H:%M" | tr '@' '\`'; fi`; IPSUPD2=`echo $IPSUPD | tr '\`' '@'`; if [ -f $FWDIR/state/local/AMW/local.IPS.set ]; then if ((($NOW-`grep -A2 "sd_last_update_time" $FWDIR/state/local/AMW/local.IPS.set | tr -dc '[0-9]'`) > 604800 )); then IPSUPD="${RED}${TXT}${IPSUPD}"; fi; fi esac
	  INST=`cpstat fw | grep "Policy name" | cut -c 15-`; echo -n .
	  TIME=`cpstat fw | grep "Install time" | awk '{print $4" "$5" "$7" \`"$6}' | cut -d':' -f1,2`; echo -n .
	  BLADES=`enabled_blades | sed 's/fw/01FW/g' | sed 's/cvpn/07MOB/g' | sed 's/vpn/02VPN/g' | sed 's/ips/03IPS/g' | sed 's/appi/04AppC/g' | sed 's/urlf/05URLF/g' | sed 's/SSL_INSPECT/06HTTPS-Inspect/g' | sed 's/av/08AV/g' | sed 's/anti_bot/09ABot/g' | sed 's/aspm/10AntiSpam/g' | sed 's/identityServer/11IA/g' | sed 's/mon/12MON/g' | sed 's/dlp/13DLP/g' | sed 's/qos/14QoS/g' | sed 's/content_awareness/15Content/g' | sed 's/ThreatEmulation/16TE/g' | sed 's/Scrub/17TX/g' | tr ' ' '\n' | sort -u | tr -d '0123456789' | tr '\n' , | sed s'/,$/\n/' | sed 's/,/, /g'`; if [[ -n `pidof in.geod` ]]; then BLADES+=", GeoP"; fi; echo -n .
	  if [[ $BLADES == *"IPS"*  ]]; then IPS=`ips stat`; IPSMODE=`echo "$IPS" | grep Detect | awk '{print $NF}'`; if [[ $IPSMODE == "Off" ]]; then IPSMODE="Prevent Mode"; else IPSMODE="${RED}${TXT}${BOLD}Detect Mode${NORM}"; fi; IPSBYPASS=`echo "$IPS" | grep Bypass | awk '{print $NF}'`; if [[ $IPSBYPASS == "Off" ]]; then IPSBYPASS="No Bypass"; else IPSBYPASS="Load Bypass"; fi; ISUPD=1; fi
	  if [[ $BLADES == *"VPN"* ]]; then VPNTUN=`vpn tu tlist`; VPNUSR=`echo "$VPNTUN" | grep -c User:`; VPNGW=`echo "$VPNTUN" | grep -c Peer:`; VPNGW=$((VPNGW-VPNUSR)); fi
	  if [[ $BLADES == *"AppC"* ]]; then if [[ -e $FWDIR/appi/update/Version ]]; then APPUPD=`date -r $FWDIR/appi/update/Version +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $FWDIR/appi/update/Version +%s 2>/dev/null`) > 604800 )); then APPUPD="${RED}${TXT}${APPUPD}"; fi; else APPUPD="${RED}${TXT}Initial state"; fi; ISUPD=1; fi
	  if [[ $BLADES == *"URLF"* ]]; then if [[ -e $FWDIR/appi/update/urlf_db.bin ]]; then URLUPD=`date -r $FWDIR/appi/update/urlf_db.bin +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $FWDIR/appi/update/urlf_db.bin +%s 2>/dev/null`) > 604800 )); then URLUPD="${RED}${TXT}${URLUPD}"; fi; else URLUPD="${RED}${TXT}Initial state"; fi; ISUPD=1; fi
	  if [[ $BLADES == *"AV"*   ]]; then if [[ -e $FWDIR/amw_kss/update/Version ]]; then AVUPD=`date -r $FWDIR/amw_kss/update/Version +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $FWDIR/amw_kss/update/Version +%s 2>/dev/null`) > 604800 )); then AVUPD="${RED}${TXT}${AVUPD}"; fi; else AVUPD="${RED}${TXT}Initial state"; fi; if [[ `cpstat -f subscription_status antimalware | grep "xpire" | grep Virus | wc -l` != "0" ]]; then AVEXP="${RED}${TXT}Expiration"; fi; ISUPD=1; fi
	  if [[ $BLADES == *"ABot"* ]]; then if [[ -e $FWDIR/amw/update/Version ]]; then ABUPD=`date -r $FWDIR/amw/update/Version +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $FWDIR/amw/update/Version +%s 2>/dev/null`) > 604800 )); then ABUPD="${RED}${TXT}${ABUPD}"; fi; else ABUPD="${RED}${TXT}Initial state"; fi; if [[ `cpstat -f subscription_status antimalware | grep "xpire" | grep Bot | wc -l` != "0" ]]; then ABEXP="${RED}${TXT}Expiration"; fi; ISUPD=1; fi
	  if [[ $BLADES == *"GeoP"* ]]; then if [[ -e $FWDIR/tmp/geo_location_tmp/updates/IpToCountry.csv ]]; then GEOUPD=`date -r $FWDIR/tmp/geo_location_tmp/updates/IpToCountry.csv +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $FWDIR/tmp/geo_location_tmp/updates/IpToCountry.csv +%s 2>/dev/null`) > 604800 )); then GEOUPD="${RED}${TXT}${GEOUPD}"; fi; else GEOUPD="${RED}${TXT}Initial state"; fi; ISUPD=1; fi
	  if [[ `egrep $'has_addr_info|:monitor_only' $FWDIR/state/local/FW1/local.set | grep -A1 addr | grep ':monitor_only (true)' | wc -l` == "0" ]]; then SPOOF="Prevent"; else SPOOF="${RED}${TXT}Detect"; fi
	  if [[ `grep ":has_addr_info (false)" $FWDIR/state/local/FW1/local.set | wc -l` != "0" ]]; then SPOOF="${RED}${TXT}None"; fi
	  if [[ `fw ctl get int fw_antispoofing_enabled` == *"0" ]]; then SPOOF="${RED}${TXT}None"; fi
	  if [[ `dynamic_objects -l | tr -d '\n'` != *"empty"* ]] && [[ `dynamic_objects -l | tr -d '\n'` != *"not exist"* ]] && [[ `dynamic_objects -l|grep object|sed '/CPDShield/d'|wc -l` -ne 0 ]]; then DYNOBJ="${CYAN}Dynamic Objects!"; ISUPD=1; fi
	  if [[ `cpprod_util FwIsUsermode` -ne 0 ]]; then BLADES="US${BLADES}"; fi
	  if [[ `grep -c aes /proc/cpuinfo` == 0 ]]; then AES=""; else AES="| ${BOLD}AES-NI${NORM} "; fi
	  elif [[ $SYSTEM != "MHO" ]]; then
		if [[ `cp_conf client get` == *'ny'* ]]; then GUICLIENT="${RED}${TXT}Any"; else GUICLIENT="Defined"; fi
		if [[ `grep ": ($HOST$\|ipaddr (" $MDS_FWDIR/conf/objects_5_0.C | grep -A1 ": ($HOST" | tac | tr -d '()\t: ' | tr '\n' ' ' | sed -e "s/^ipaddr//" -e "s/ $//"` != `grep $HOST$ /etc/hosts` ]]; then MGMTNAME="${RED}${TXT}Object name or IP unlike /etc/hosts (sk112914)"; else MGMTNAME="Consistent"; fi
		if [[ "$SYSTEM" == *'Standby'* ]] || [[ -z `grep crldp_name $CPDIR/registry/HKLM_registry.data` ]]; then ICANAME="-"; elif [[ `grep crldp_name $CPDIR/registry/HKLM_registry.data|cut -d "(" -f2|cut -d ")" -f1|cut -d "." -f1` != "$HOST" ]]; then ICANAME="${RED}${TXT}Unlike Hostname (sk42071)"; else ICANAME="Consistent"; fi
		if [[ `grep -B3 :ClassName\ \(host_ckp\) $MDS_FWDIR/conf/objects_5_0.C | grep :\ \( | tr -d ':(\t' | tr '\n' ' '` != *"$HOST"* ]]; then MGMTHOST="${RED}${TXT}Security Management not defined as host"; else MGMTHOST="Security Management defined as host"; fi
		if [[ -e $RTDIR/conf/ip2country.csv ]]; then IP2C=`date -r $RTDIR/conf/ip2country.csv +"%b %d %Y @%H:%M" 2>/dev/null | tr '@' '\`'`; if ((($NOW-`date -r $RTDIR/conf/ip2country.csv +%s 2>/dev/null`) > 2592000 )); then IP2C="${RED}${TXT}${IP2C}"; fi; else IP2C="-"; fi
	fi
	case `echo ${OS#*R*}` in 77.30) : ;; *) [ $ISGW == 0 ] && { CPMSTAT=`$FWDIR/scripts/cpm_status.sh | cut -c 43-`; APISTAT=`api status | grep 'Overall' | sed 's/Overall API Status: //'`; APIVER=`ls $FWDIR/api/docs/data/ | tr 'v\n' ' ' | awk '{print $NF}'`; } esac
	if [[ `grep "ALL: ALL" /etc/hosts.allow | wc -l` == "0" ]]; then ACCESS="Defined"; else ACCESS="${RED}${TXT}Any"; fi
	if [[ -e /proc/net/vlan/config ]]; then if [[ `cat /proc/net/vlan/config | sed '0,/VID/d' | awk '{print $NF}' | sort -u | wc -l` != "0" ]]; then VLANS="Defined"; if [[ `cat /proc/net/vlan/config | sed '0,/VID/d' | awk '{print $NF}' | sort -u | xargs -I {} grep interface:{}: /config/db/initial | grep ipaddr | wc -l` != "0" ]]; then VLANS="${RED}${TXT}IP on VLAN trunk not supported - sk88700"; fi; fi; fi
	ROOT=`df / | grep " /" | tr '%' ' ' | awk '{print $(NF-1)}'`; if [[ $ROOT -gt "69" ]]; then ROOT="${RED}${TXT}${ROOT}%"; else ROOT+="%"; fi;
	VARlog=`df /var/log | grep " /" | tr '%' ' ' | awk '{print $(NF-1)}'`; if [[ $VARlog -gt "69" ]]; then VARlog="${RED}${TXT}${VARlog}%"; else VARlog+="%"; fi;
	UPTIME=`</proc/uptime`; UPTIME=${UPTIME%%.*}
	MINS=$((UPTIME/60%60)); HOURS=$((UPTIME/60/60%24)); DAYS=$((UPTIME/60/60/24))
	if     [[ $DAYS -gt "3" ]]; then UPTIME="$DAYS days"
	  elif [[ $DAYS -ne "0" ]]; then UPTIME="$DAYS days, $HOURS hours"
	  elif [[ $DAYS -eq "0" && $HOURS -eq "0" ]]; then UPTIME="$MINS minutes"
	  else UPTIME="$HOURS hours, $MINS minutes"
	fi

	saida="<tr><td><span id='middleIntroText' class='IntroductionText'><b>Host</b><br><b>IP</b><br><b>System</b><br><b>Type</b><br><b>OS</b><br><b>CPuse</b><br>
			<b>Host Acess</b><br><b>Processador</b><br><b>CPU</b><br><b>RAM</b><br><b>SecureXL</b><br><b>CoreXL</b><br><b>Core Dumps</b><br><b>Disk use</b><br><b>Uptime</b>
			</span></td><td><span id='middleIntroText' class='IntroductionText'>${HOST}<br>${HOSTIP}<br>${SYSTEM}${MHOTYPE}<br>${VSTYPE}${TYPE}<br>R${OS#*R*} GAiA ${KERNEL} JHF (Take ${JUMBO}) @ ${OSMODE}-bit<br>
			${CPUSE}<br>${ACCESS}<br>${CPUMOD}<br>${CORE} Cores<br>${RAM} GB (${TAG}: ${FREE} GB) | ${SWAP}<br>$SXL | Multi-Queue Interfaces $CPMQ<br>$CXL ($LIC Cores) | Dyn. Dispatcher: ${DYN} | Split: $SPLIT<br>
			${DUMPS} | Crash dumps: ${CRASH}<br>${ROOT} | /var/log/ ${VARlog}<br>${UPTIME} | NTP: ${NTIME}</span></td></tr>"
	
	if [[ $ISGW -eq "0" ]] && [[ "$SYSTEM" != "MHO" ]]; then
		saida+="<tr><td><span id='middleIntroText' class='IntroductionText'><b>GUI Client</b><br><b>CPM Status</b><br><b>IP2Country</b><br><b>ICA Name</b><br><b>MGMT API</b><br>
				<b>MGMT Name</b><br><b>MGMT Host</b><br></span></td><td><span id='middleIntroText' class='IntroductionText'>${GUICLIENT}<br>${CPMSTAT}<br>${IP2C}<br>
				${ICANAME}<br>${APISTAT} | Version ${APIVER}<br>${MGMTNAME}<br>${MGMTHOST}</span></td></tr>"
	fi

	if [[ $ISGW -eq "1" ]]; then
		saida+="<tr><td><span id='middleIntroText' class='IntroductionText'><b>Managed by</b><br><b>Policy</b><br><b>Inspection</b><br><b>Blades</b><br>
				</span></td><td><span id='middleIntroText' class='IntroductionText'>$MGMT (IP: ${MGIP:1:${#MGIP}-2})<br>"
							
		if [[ -n $VSTYPE ]]; then if [[ $VSTYPE == *"Switch"* ]] || [[ $VSTYPE == *"Router"* ]]; then saida+="<Not applicable><br>"; else saida+="${INST} - ${TIME}<br>"; fi; else saida+="${INST} - ${TIME}<br>"; fi					
		if [[ -n $VSTYPE ]]; then if [[ $VSTYPE == *"Switch"* ]] || [[ $VSTYPE == *"Router"* ]]; then saida+="<Not applicable><br>"; else saida+="$STATE | Address Spoofing: $SPOOF<br>"; fi; else saida+="$STATE"; if [[ -e /etc/cloud-version ]]; then echo; else saida+=" | Address Spoofing: $SPOOF<br>"; fi; fi
		if [[ -n $VSTYPE ]]; then if [[ $VSTYPE == *"Switch"* ]] || [[ $VSTYPE == *"Router"* ]]; then saida+="<Not applicable><br>"; else saida+="${BLADES}<br>"; fi; else saida+="${BLADES}<br>"; fi

							
		saida+="</span>	</td></tr><tr><td><span id='middleIntroText' class='IntroductionText'><b>"
						
		  if [[ $BLADES == *"VPN"*  ]]; then saida+="VPN<br>"; fi
		  if [[ $BLADES == *"IPS"*  ]]; then saida+="IPS<br>"; fi
		  if [[ $BLADES == *"AppC"* ]]; then saida+="AppC<br>"; fi
		  if [[ $BLADES == *"URLF"* ]]; then saida+="URLF<br>"; fi
		  if [[ $BLADES == *"ABot"* ]]; then saida+="ABot<br>"; fi
		  if [[ $BLADES == *"AV"*   ]]; then saida+="AV<br>"; fi
		  if [[ $BLADES == *"GeoP"* ]]; then saida+="GeoP<br>"; fi
		  if [[ -n $DYNOBJ ]]; then saida+="INFO<br>"; fi						
						
						
		saida+="</b></span></td><td><span id='middleIntroText' class='IntroductionText'>"
						
		  if [[ $BLADES == *"VPN"*  ]]; then saida+="Tunnels: ${VPNGW} | Remote Access Users: ${VPNUSR}<br>"; fi
		  if [[ $BLADES == *"IPS"*  ]]; then saida+="${IPSUPD} | ${IPSMODE} | ${IPSBYPASS}<br>"; fi
		  if [[ $BLADES == *"AppC"* ]]; then saida+="${APPUPD}<br>"; fi
		  if [[ $BLADES == *"URLF"* ]]; then saida+="${URLUPD}<br>"; fi
		  if [[ $BLADES == *"ABot"* ]]; then saida+="${ABUPD}   ${ABEXP}<br>"; fi
		  if [[ $BLADES == *"AV"*   ]]; then saida+="${AVUPD}   ${AVEXP}<br>"; fi
		  if [[ $BLADES == *"GeoP"* ]]; then saida+="${GEOUPD}<br>"; fi
		  if [[ -n $DYNOBJ ]]; then saida+="${DYNOBJ}<br>"; fi						
						
		saida+="</span></td></tr>"
	fi


	saida+="<tr><td><span id='middleIntroText' class='IntroductionText'><b>"
	if [[ -n $MAC ]]; then saida+="Serial<br>"; fi
	if [[ -n $MAC ]]; then saida+="PSU<br>"; fi
	saida+="Interfaces<br>"
	if [[ -n $SYNC ]]; then saida+="SYNC Ifs<br>"; fi
	if [[ -n $SNMP ]]; then saida+="SNMP<br>"; fi
	saida+="BACKUP<br>RAID</b></span></td><td><span id='middleIntroText' class='IntroductionText'>"
	if [[ -n $MAC ]]; then saida+="${SERIAL} | MAC: ${MAC}<br>"; fi
	if [[ -n $MAC ]]; then saida+="${PSU}<br>"; fi
	saida+="${DRIVER} "
	if [[ -n $VLANS ]]; then saida+="VLANs  ${VLANS}"; fi
	saida+="<br>"
	if [[ -n $SYNC ]]; then saida+="${SYNC}<br>"; fi
	if [[ -n $SNMP ]]; then saida+="${SNMP}<br>"; fi
	saida+="${BCKP}<br>${RAID}<br></span></td></tr>"
		
	echo "$saida" >> $DIR/Validacao/old_stats

}






func_grafico_cpu() {
arquivo="$DIR/Graficos/grafico_consumo_cpu.html"


txt_html='<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Gráfico de Consumo de CPU</title>
<!-- Incluir Highcharts -->
  <script src="https://code.highcharts.com/highcharts.js"></script>
  <script src="https://code.highcharts.com/highcharts-more.js"></script>
  <script src="https://code.highcharts.com/modules/exporting.js"></script>
<style type="text/css">
#container {height: 600px;width: 100%;}
</style>
</head>
<body>
<div id="container"></div>
<script type="text/javascript">
var opcoes = {
  chart: {
    zoomType: "x",
    type: "line"
  },
  title: {
    text: "Consumo de CPU '

   txt_html+=" - `hostname`"
   txt_html+='" },'  
   echo $txt_html >> $arquivo

txt_html=' 
  xAxis: {
    type: "datetime",
    dateTimeLabelFormats: {
      second: "%H:%M:%S"
    }
  },
  yAxis: {
    title: {
      text: "% de consumo"
    },
    min: 0,
    max: 100
  },
  tooltip: {
    formatter: function () {
      return "<b>" + this.series.name + "</b><br>" +
        Highcharts.dateFormat("%d/%m/%Y %H:%M:%S", this.x) + "<br>" +
        "Consumo: " + this.y + "%";
    }
  },'

echo $txt_html >> $arquivo

query="
SELECT name_of_cpu, strftime('%Y,', Timestamp, 'unixepoch', 'localtime') 
|| (cast(strftime('%m', Timestamp, 'unixepoch', 'localtime') as int)-1) 
|| strftime(',%d,%H,%M,%S', Timestamp, 'unixepoch', 'localtime') Data, 
cpu_usage, b.val nome_cpu
from UM_STAT_UM_CPU_UM_CPU_ORDERED_TABLE a join cpview_ref_table b on b.seq = a.cpu_type
where  cpu_usage >= 50  OR (timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_CPU_UM_CPU_ORDERED_TABLE) - 864000 and cpu_usage > 0)
order by name_of_cpu, timestamp"

sqlite3 -separator ';' "$database" "$query" |
awk -F ';' '{
   if (NR==1) {
      printf("series: dados = [\n{\n")
      prev = -1;
   }
   if (prev != $1) {
      if (prev != -1) printf("]\n},\n{\n")
      printf("name: '\''CPU %d %s'\'', \ndata: [\n", $1, $4)
      printf("[Date.UTC(%s),%d]\n",$2,$3)
      prev = $1
   } else {
     printf(",[Date.UTC(%s),%d]\n", $2, $3)
  }
} END {
printf("]}\n]")
}' >> $arquivo

echo "}; Highcharts.chart(container, opcoes); </script> </body> </html>" >> $arquivo

sqlite3 "$database" ".exit"

}


func_grafico_interface() {
arquivo="$DIR/Graficos/grafico_throughput_interfaces.html"


txt_html='<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Gráfico de Throughput das Interfaces</title>
<!-- Incluir Highcharts -->
<script src="https://code.highcharts.com/highcharts.js"></script>
<script src="https://code.highcharts.com/modules/exporting.js"></script>
<script src="https://code.highcharts.com/modules/export-data.js"></script>

<style type="text/css">
#container {height: 600px;width: 100%;}
</style>
</head>
<body>
<div id="container"></div>
<script type="text/javascript">
var opcoes = {
  chart: {
    zoomType: "x",
    type: "line"
  },
  title: {
    text: "Throughput das Interfaces'

  txt_html+=" - `hostname`"
  txt_html+='" },'  

  txt_html+='
  xAxis: {
    type: "datetime",
    dateTimeLabelFormats: {
      second: "%H:%M:%S"
    }
  },
  yAxis: {
    title: {
      text: "Throughput"
    }
  },
  tooltip: {
    formatter: function () {
      var throughput = Math.floor(this.y / 1048576);
      return "<b>" + this.series.name + "</b><br>" +
        Highcharts.dateFormat("%d/%m/%Y %H:%M:%S", this.x) + "<br>" +
        "Throughput: " + throughput + " MiB" ;
    }
  },'


echo $txt_html >> $arquivo

query='
select b.val || " - TX" nome, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data, 
if_tx_bits_throughput throughput
from UM_STAT_UM_HW_UM_IF_TX_STATISTICS_TABLE a join cpview_ref_table b on a.if_name = b.seq
where if_tx_bits_throughput > 0 and b.val <> "TOTAL" and timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_HW_UM_IF_TX_STATISTICS_TABLE) - 864000
union
select b.val || " - RX" nome, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data,  
if_rx_bits_throughput throughput
from UM_STAT_UM_HW_UM_IF_RX_STATISTICS_TABLE a join cpview_ref_table b on a.if_name = b.seq
where if_rx_bits_throughput > 0 and b.val <> "TOTAL" and timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_HW_UM_IF_RX_STATISTICS_TABLE) - 864000
order by nome'



sqlite3 -separator ';' "$database" "$query" |
awk -F ';' '{
   if (NR==1) {
      printf("series: dados = [\n{\n")
      prev = -1;
   }
  if (prev != $1) {
      if (prev != -1) printf("]\n},\n{\n")
      printf("name: '\''%s'\'', \ndata: [\n", $1)
      printf("[Date.UTC(%s),%d]\n",$2,$3)
      prev = $1
   } else {
     printf(",[Date.UTC(%s),%d]\n", $2, $3)
  }
} END {
printf("]}\n]")
}' >> $arquivo

echo "}; Highcharts.chart(container, opcoes); </script> </body> </html>" >> $arquivo

sqlite3 "$database" ".exit"

}


func_grafico_memoria() {
arquivo="$DIR/Graficos/grafico_consumo_memoria.html"


txt_html='<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Gráfico de Consumo de Memoria</title>
<!-- Incluir Highcharts -->
<script src="https://code.highcharts.com/highcharts.js"></script>
<script src="https://code.highcharts.com/modules/exporting.js"></script>
<script src="https://code.highcharts.com/modules/export-data.js"></script>

<style type="text/css">
#container {height: 600px;width: 100%;}
</style>
</head>
<body>
<div id="container"></div>
<script type="text/javascript">
var opcoes = {
  chart: {
    zoomType: "x",
    type: "line"
  },
  title: {
    text: "Consumo de Memoria'

  txt_html+=" - `hostname`"
  txt_html+='" },' 


txt_html+='
  xAxis: {
    type: "datetime",
    dateTimeLabelFormats: {
      second: "%H:%M:%S"
    }
  },
  yAxis: {
    title: {
      text: "Memoria"
    }
  },
  tooltip: {
    formatter: function () {
      var memoria = Math.floor(this.y / 1048576);
      return "<b>" + this.series.name + "</b><br>" +
        Highcharts.dateFormat("%d/%m/%Y %H:%M:%S", this.x) + "<br>" +
        "Memoria: " + memoria + " MiB" ;
    }
  },'


echo $txt_html >> $arquivo

query='
select "Memoria Real Total" tipo, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data, 
real_total valor , "square" linha
from UM_STAT_UM_MEMORY where timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_MEMORY) - 864000
union
select "Memoria Real Usada" tipo, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data, 
real_used valor  , "square" linha
from UM_STAT_UM_MEMORY where timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_MEMORY) - 864000
union
select "Memoria Swap Total" tipo, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data,  
swap_total valor , "circle" linha
from UM_STAT_UM_MEMORY where timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_MEMORY) - 864000
union
select "Memoria Swap Usada" tipo, strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1) 
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data, 
swap_used valor , "circle" linha
from UM_STAT_UM_MEMORY where timestamp >= (SELECT MAX(timestamp) FROM UM_STAT_UM_MEMORY) - 864000
order by tipo'



sqlite3 -separator ';' "$database" "$query" |
awk -F ';' '{
   if (NR==1) {
      printf("series: dados = [\n{\n")
      prev = -1;
   }
  if (prev != $1) {
      if (prev != -1) printf("]\n},\n{\n")
      printf("name: '\''%s'\'', marker: { symbol: '\''%s'\''}, \ndata: [\n",$1, $4)
      printf("[Date.UTC(%s),%d]\n",$2,$3)
      prev = $1
   } else {
     printf(",[Date.UTC(%s),%d]\n", $2, $3)
  }
} END {
printf("]}\n]")
}' >> $arquivo

echo "}; Highcharts.chart(container, opcoes); </script> </body> </html>" >> $arquivo

sqlite3 "$database" ".exit"

}



func_grafico_spike() {
arquivo="$DIR/Graficos/grafico_spike.html"

txt_html="
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Gráfico de Spikes por CPU e Processo</title>
<!-- Incluir Highcharts -->
  <script src='https://code.highcharts.com/highcharts.js'></script>
  <script src='https://code.highcharts.com/highcharts-more.js'></script>
<style type='text/css'>
#container {height: 600px;width: 100%;}
</style>
</head>
<body>
<div id='container'></div>
<script type='text/javascript'>
var options = {
chart: {
type: 'bubble',
plotBorderWidth: 1,
plotBorderColor: '#ddd',
zoomType: 'xy'
},
title: {
text: 'Gráfico de Spikes por CPU e Processo - `hostname`'
},
 xAxis: {
    type: 'datetime',
    tickInterval: 86400000,
    minRange: 2592000000
       },
yAxis: {
title: {
text: 'Hora'
},
min: 0,
max: 24,
tickInterval: 1,
labels: {
formatter: function() {
return this.value + ':00';
}
}
},
tooltip: {
headerFormat: '<b>{series.name}</b><br>',
pointFormat: 'Processo: {point.processo}<br>Data: {point.x:%e/%m/%Y} {point.hora}<br>Consumo: {point.z}%<br>Duracao: {point.duracao}s'
},"

echo $txt_html >> $arquivo

query='Select strftime("%Y,", Timestamp, "unixepoch", "localtime") 
|| (cast(strftime("%m", Timestamp, "unixepoch", "localtime") as int)-1)
|| strftime(",%d,%H,%M,%S", Timestamp, "unixepoch", "localtime") Data,
cpu_core, cpu_spike_duration, cpu_avg_usage, cpu_top_consumer
, (select val from cpview_ref_table b where seq = (select cpu_type from UM_STAT_UM_CPU_UM_CPU_ORDERED_TABLE c where c.name_of_cpu = a.cpu_core LIMIT 1) limit 1) tipo
From spike_detective_cpu_spike_cpu_table a where a.cpu_spike_start_time >= (SELECT MAX(cpu_spike_start_time) FROM spike_detective_cpu_spike_cpu_table) - 864000
Order By cpu_core, Data'

sqlite3 -separator ',' "$database" "$query" |
awk -F ',' '{
   if (NR==1) {
      printf("series: [\n{\n")
      prev = -1;
   }
   if (prev != $7) {
      if (prev != -1) printf("]\n},\n{\n")
      printf("name: '\''CPU %d %s'\'', \ndata: [\n", $7, $11)
      printf("{x:Date.UTC(%s,%s,%s,%s,%s,%s),y:%d.%d,z:%d,processo: '\''%s'\'',hora: '\''%s:%s'\'',duracao: %d}\n",$1,$2,$3,$4,$5,$6,$4,($5/60*100),$9,$10,$4,$5,$8)
      prev = $7
   } else {
     printf(",{x:Date.UTC(%s,%s,%s,%s,%s,%s),y:%d.%d,z:%d,processo: '\''%s'\'',hora: '\''%s:%s'\'',duracao: %d}\n",$1,$2,$3,$4,$5,$6,$4,($5/60*100),$9,$10,$4,$5,$8)
  }
} END {
printf("]}\n]")
}' >> $arquivo

echo "}; Highcharts.chart(container, options); </script> </body> </html>" >> $arquivo

sqlite3 "$database" ".exit"

}

main
