package cic.cs.unb.ca.ifm;


import cic.cs.unb.ca.Sys;
import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PcapIfWrapper;
import cic.cs.unb.ca.jnetpcap.worker.LoadPcapInterfaceWorker;
import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import swing.common.InsertTableRow;
import swing.common.JTable2CSVWorker;
import swing.common.SwingUtils;
import swing.common.TextFileFilter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Consumer;


class StreamGobbler implements Runnable {
    private InputStream inputStream;
    private Consumer<String> consumer;

    public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
        this.inputStream = inputStream;
        this.consumer = consumer;
    }

    @Override
    public void run() {
        new BufferedReader(new InputStreamReader(inputStream)).lines()
                .forEach(consumer);
    }
}
enum FileBuffer
{    FILE_INITIAL,
    FILE_UNCHANGED,
    FILE_CHANGED,
    FILE_ROTATED
}




public class Shell {
    private static String previousTime="";
    private static DateTimeFormatter formatter;
    private static int counter=0;
    private static int counterIn=0;
    private static int counterOut=0;
    private static TrafficFlowWorker mWorker;
    private static ExecutorService csvWriterThread;
    public static boolean isDiscovering=true;
    public static final Logger logger = LoggerFactory.getLogger(FlowGenerator.class);
    public static List<String> interfaces =new ArrayList<>();
    public static int totalCounter=0;
    public static int fileCounter=1;
    public static FileBuffer fileBuffer=FileBuffer.FILE_INITIAL;

    private static void init() {
        csvWriterThread = Executors.newSingleThreadExecutor();
    }

    public void destory() {
        csvWriterThread.shutdown();
    }
    private static  void loadPcapIfs(Boolean doPrint) {
        LoadPcapInterfaceWorker task = new LoadPcapInterfaceWorker();

        task.addPropertyChangeListener(event -> {

            if ("state".equals(event.getPropertyName())) {
                LoadPcapInterfaceWorker task1 = (LoadPcapInterfaceWorker) event.getSource();

                switch (task1.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {

                            java.util.List<PcapIf> ifs = task1.get();

                            List<PcapIfWrapper> pcapiflist = PcapIfWrapper.fromPcapIf(ifs);
                            System.out.println("/n list of interfaces available on device");
                            for(PcapIfWrapper pcapif :pcapiflist) {
                                if(doPrint){
                                    System.out.println(pcapif.toString());}
                                interfaces.add(pcapif.toString().split(" ")[0]);
                                isDiscovering=false;


                            }

                        } catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }
                        break;
                }
            }
        });
        task.execute();
    }

    public static void main(String[] args) throws InterruptedException, IOException {
        String root= System.getProperty("user.dir");
        String iface="";
        String customDirectory="";

        init();
        formatter= DateTimeFormatter.ofPattern("dd-MM-yy HH:mm:ss");
        previousTime=LocalDateTime.now().format(formatter);
        int index;

        loop:
        for (index = 0; index < args.length; index++) {
            String opt = args[index];
            switch (opt) {
                case "--list":
                {
                    getIfaces(true);
                    break;

                }
                case "-v" :{
                    System.out.println("version:4.0");
                    break;
                }

                case "--gui":
                {
                    String[] appArgs={};
                    App.main(appArgs);
                    break;
                }
                case "-d":
                {
                	try {
                		customDirectory = args[index + 1];
                		System.out.println(customDirectory);
                		File file =new File(customDirectory);
                        try
                        {
                        	if(!file.isDirectory())
                        	{
                        		file.mkdirs();
                        	}
                        	
                        }
                        catch (Exception e)
                        {
                        	System.out.println("error creating file");
                        	return;
                        }
                		
                	}
                	catch (Exception e) {
                		error("error no such directory");
                	}
                	break;
                	}
                case "-i":
                    try {
                        iface = args[index + 1];

                        if (iface.charAt(0) == '-' || iface.toLowerCase().equals("start") || iface.toLowerCase().equals("stop")) {
                            error("No interface specified");
                        } else {
                            getIfaces(false);
                            TimeUnit.SECONDS.sleep(3);

                            for (String s:interfaces)
                            {
                                System.out.println(s);
                            }



                            if(!interfaces.contains(iface))
                            {   System.out.println(iface+ ": interface not found ");
                                return;
                            }

                            logger.info(iface);

                        }
                    } catch (Exception e) {
                        error("No interface specified");
                    }
                    break;
                case "start":
                    String rootPath= System.getProperty("user.dir");
                    StringBuilder sb=new StringBuilder(rootPath);
                    sb.append(Sys.FILE_SEP).append("data").append(Sys.FILE_SEP).append("daily").append(Sys.FILE_SEP);
                    System.out.println("Packet Will be saved on:"+sb.toString());
                    rootPath= System.getProperty("user.dir");
                    sb=new StringBuilder(rootPath);
                    sb.append(Sys.FILE_SEP).append("data").append(Sys.FILE_SEP).append("daily").append(Sys.FILE_SEP);
                    File file =new File(sb.toString());
                    String todayFile = LocalDate.now().toString()+FlowMgr.FLOW_SUFFIX;

                    if(file!=null) {
                        String[] fileList=file.list();
                        if(file.list()!=null) {
                            for (String s : fileList) {
                                if (s.contains(todayFile)) {
                                    try {
                                        String val = (s.split(todayFile)[1]).split(".csv")[0];
                                        if (Integer.parseInt(val) >= fileCounter)
                                            fileCounter = Integer.parseInt(val) + 1;

                                    } catch (Exception e) {
                                    }

                                }
                            }
                        }
                    }
                    else
                    {
                        fileCounter=1;
                    }
                    File saveCsvFileFullPath = new File(sb.toString()+todayFile+fileCounter+FlowMgr.CSV_SUFFIX);
                    long csvLines = SwingUtils.countLines(saveCsvFileFullPath.getPath());
                    if(csvLines >=100) {
                        fileCounter++;
                    }
                    startTrafficFlow(iface);
                    while(true){}
                case "tcpdump":{
                    System.out.println("using tcpdump to capture the traffic");
                    String argument[]={iface,customDirectory};
                    ShellFile.main(argument);
                    System.out.println("succesfully capture the packet");


                }
                case "stop":
                    System.out.println("packet capturing stopped");
                    break;
                default:
                    if (!opt.isEmpty() && opt.charAt(0) == '-') {
                        error("Unknown option: '" + opt + "'");
                    }
                    break;
            }
        }
        if (index <= 0) {
            error("\n Missing argument(s)");
        } // Run the application // ...


    }
    private static void getIfaces(Boolean doPrint)
    {
        Thread t1 = new Thread(new Runnable(){

            public  void run()
            {
                loadPcapIfs(doPrint);
                while (isDiscovering)
                {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }


            }});
        t1.start();
    }
    private static void error(String message) {
        if (message != null) {
            System.err.println(message);
        }
        System.err.println("usage: CICFlow[-v].jar [options] \n options: \n -i: interface name  \n -d:directory \n  --gui: to launch gui \n  --list: list all interfaces \n  usage:  \n \t -i wlan0 <start/tcpdump> \n \t to provide output directory \n \t   -i wlan0 -d [directory] <start/tcpdump>  " );
        System.exit(1);
    }



    public static void convertFile(String filePath,String pcapFileCounter,String todayFileName,String csvFileCounter) throws IOException, InterruptedException {

        String pcapFilename=filePath+"traffic"+pcapFileCounter+".pcap";

        String csvFilename=todayFileName+csvFileCounter+FlowMgr.CSV_SUFFIX;
        System.out.println("converting file"+pcapFilename+" to csv file"+ csvFilename);
        String[] arg = {pcapFilename, filePath,csvFilename};
        ShellFile.main(arg);
    }














    private static void startTrafficFlow(String ifName){
        if (mWorker != null && !mWorker.isCancelled()) {
            return;
        }
        System.out.println("packet capture starting on interface "+ ifName);
        mWorker = new TrafficFlowWorker(ifName);
        mWorker.addPropertyChangeListener(event -> {
            TrafficFlowWorker task = (TrafficFlowWorker) event.getSource();
            if("progress".equals(event.getPropertyName())){

            }else if (TrafficFlowWorker.PROPERTY_FLOW.equalsIgnoreCase(event.getPropertyName())) {

                BasicFlow flow= (BasicFlow) event.getNewValue();
                insertFlow(flow);
            }else if ("state".equals(event.getPropertyName())) {
                switch (task.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            logger.info(task.get());
                        } catch(CancellationException e){
                            logger.info("Pcap stop listening");

                        }catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }

                }
            }
        });
        mWorker.execute();

    }








    private static void insertFlow(BasicFlow flow) {
        List<String> flowStringList = new ArrayList<>();
        List<String[]> flowDataList = new ArrayList<>();
        String flowDump = flow.dumpFlowBasedFeaturesEx();
        flowStringList.add(flowDump);
        flowDataList.add(StringUtils.split(flowDump, ","));
        //write flows to csv file
        String rootPath= System.getProperty("user.dir");
        StringBuilder sb=new StringBuilder(rootPath);
        sb.append(Sys.FILE_SEP).append("data").append(Sys.FILE_SEP).append("daily").append(Sys.FILE_SEP);
        String header  = FlowFeature.getHeader();
        String path = sb.toString();
        String packetId=StringUtils.split(flowDump, ",")[0];
        System.out.println("packet:"+packetId);
        String time=LocalDateTime.now().format(formatter);
        String countFileName =LocalDate.now().toString()+"_count" + FlowMgr.FLOW_SUFFIX;
        String count_header = "time,count,count In,count Out";
        List<String> FlowCountList = new ArrayList<String>();
        String packetCountRow;
        if (Integer.parseInt(previousTime.split(":")[2]) == Integer.parseInt(time.split(":")[2]))
        {   counter ++;
        }
        else
        {   if(counter!=0)
        {
            packetCountRow =previousTime.split(" ")[1]+","+String.valueOf(counter)+","+counterIn+","+counterOut;
            FlowCountList.add(packetCountRow);
            csvWriterThread.execute(new InsertCsvRow(count_header, FlowCountList,path,countFileName));
        }
            counter = 1;
            previousTime=time;
            counterIn=0;
            counterOut=0;
        }

        // checking the source ip address. packet index form is sourceIp-DestinationIP-sourcePort-DestinationPort-protocol
        //splitting the packet index to get source ip and thus checks if source ip contains 192
        if(packetId.split("-")[0].contains("192"))
        {
            counterOut++;
        }
        else{
            counterIn++;
        }

        String filename = LocalDate.now().toString() + FlowMgr.FLOW_SUFFIX+fileCounter+FlowMgr.CSV_SUFFIX;

        csvWriterThread.execute(new InsertCsvRow(header, flowStringList, path, filename));
        totalCounter++;
        fileCounter=totalCounter>=100?fileCounter+1:fileCounter;


    }






}


















