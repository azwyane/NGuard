
package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.Sys;
import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import swing.common.SwingUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import static cic.cs.unb.ca.Sys.FILE_SEP;



public class ShellFile {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";
    private static String[] animationChars = new String[]{"|", "/", "-", "\\"};
    private static String csvFilename;
    private static String iface;
    public static String outPath="";
    public static int fileCounter=1;
    public static int count;
    private static DateTimeFormatter formatter;
    private static String previousTime="";
    private static int csvCounter=1;
    private static int pkCounter=1;
    private static int pkFileCounter=0;
    private static int packetCounter=1;
    private static String directory="";
    private static ExecutorService csvWriterThread;
    
    
    private static void init() {
        csvWriterThread = Executors.newSingleThreadExecutor();
    }

    public void destory() {
        csvWriterThread.shutdown();
    }
    
    public static void main(String[] args) throws IOException, InterruptedException {
       
        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String rootPath = System.getProperty("user.dir");
        formatter= DateTimeFormatter.ofPattern("dd-MM-yy HH:mm:ss");
        previousTime=LocalDateTime.now().format(formatter);
        StringBuilder sb=new StringBuilder(System.getProperty("user.dir")).append(FILE_SEP).append("data").append(FILE_SEP).append("daily").append(FILE_SEP);

        directory=sb.toString();
        init();
      

        if (args.length < 1) {
            logger.info("Please select interface");
            return;
        }
        iface = args[0];
        outPath= args[1];
        if(outPath.length()>=1) {
        File out = new File(outPath);
        if (out.isFile()) {
            logger.info("The out folder does not exist! -> {}",outPath);
            System.out.println("improper file direcotory");
            return;
        }
        if(!outPath.endsWith(FILE_SEP))
        {
        	outPath=outPath+FILE_SEP;
        }
        directory=outPath+LocalDate.now().toString()+FILE_SEP;
        }
        System.out.println(directory);
        
        File file =new File(directory);
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
        String todayFile = LocalDate.now().toString()+FlowMgr.FLOW_SUFFIX;
        String todayPacketFile = LocalDate.now().toString()+"_Packet";


        if(file!=null) {
            String[] fileList=file.list();
            if(file.list()!=null) {
                for (String s : fileList) {
                    if (s.contains(todayFile)) {
                        try {
                            String val = (s.split(todayFile)[1]).split(".csv")[0];
                            int value= Integer.valueOf(val);
                            if (value >= csvCounter)
                                csvCounter = value+1;

                        } catch (Exception e) {
                        }

                    }
                    if (s.contains(todayPacketFile)) {
                        try {
                            String val = (s.split(todayPacketFile)[1]).split(".csv")[0];
                            int value= Integer.valueOf(val);
                            if (value >= packetCounter)
                                packetCounter = value+1;

                        } catch (Exception e) {
                        }

                    }
                }
            }
        }
        System.out.println("csv file counter:"+csvCounter +"and packet counter :" + packetCounter);


        while(true) {

            String pcapFileName=sb+"traffic4.pcap";
            String pcapDirectory=directory;

            generatePcap(iface, pkCounter,pcapDirectory);
            pkCounter++;
            if(pkCounter>=10)
            {
                pkCounter=1;
                pkFileCounter=9;
            }
            else
            {
                pkFileCounter=pkCounter-1;
            }

            Thread pcapConversion =new Thread(new Runnable() {
                @Override
                public void run() {
                    String outFile=LocalDate.now().toString();
                    String pcapFileName=directory+"traffic"+pkFileCounter+".pcap";
                    System.out.println("thread started with pcapfilename: "+pcapFileName);
                    readPcapFile(pcapFileName, directory,outFile,csvCounter,flowTimeout,activityTimeout);
                    File out = new File(directory+outFile+FlowMgr.FLOW_SUFFIX+csvCounter+FlowMgr.CSV_SUFFIX);;
                    if (out==null||!out.isFile()) {
                    	try {
							out.createNewFile();
							System.out.println(out.toString() +" file created");
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
                    }
                    csvCounter++;

                }
            });
            if(pkFileCounter!=0) {
                pcapConversion.start();
            }

        }


}














    private static void generatePcap( String iface,int counter,String outPath) throws IOException, InterruptedException {
        
        String todayFile = LocalDate.now().toString() + FlowMgr.FLOW_SUFFIX;
        String pcapFileName=outPath+"traffic"+counter+".pcap";
 //       String[] arg={sb.toString()+"traffic"+String.valueOf(pcapFileCounter)+".pcap",sb.toString()};
        ProcessBuilder builder = new ProcessBuilder();
        System.out.println("writing on traffic"+pcapFileName);
        String cmd = "sudo tcpdump -i "+iface +" -U -v -G 15 -W 1 -c 1000 -w "+pcapFileName;
        Runtime run = Runtime.getRuntime();
        Process pr = run.exec(cmd);
        pr.waitFor();
        BufferedReader buf = new BufferedReader(new InputStreamReader(pr.getInputStream()));
                        String line = "";
                        while ((line=buf.readLine())!=null) {
                            System.out.println(line);
                        }



    }

    private static int readPcapFile(String inputFile, String outPath,String outputFile,int csvCounter, long flowTimeout, long activityTimeout) {
        if(inputFile==null ||outPath==null ) {
            return 0;
        }
        String fileName=outputFile;

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }
        packetCounter++;
        File saveFileFullPath = new File(outPath+fileName+"_Packet"+packetCounter+FlowMgr.CSV_SUFFIX);


        long lines = SwingUtils.countLines(saveFileFullPath.getPath());
        count= (int) lines;

      
        File saveCsvFileFullPath = new File(outPath+fileName+FlowMgr.FLOW_SUFFIX+csvCounter+FlowMgr.CSV_SUFFIX);
        long csvLines = SwingUtils.countLines(saveCsvFileFullPath.getPath());
//        if(csvLines >=100) {
           // csvCounter++;
//        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);


        flowGen.addFlowListener(new FlowListener(fileName,outPath,csvCounter));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s",fileName+FlowMgr.FLOW_SUFFIX+csvCounter+FlowMgr.CSV_SUFFIX));


        int nValid=0;
        int nTotal=0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        int i=0;
        while(true) {
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket !=null){
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }else{
                    nDiscarded++;
                }
            }catch(PcapClosedException e){
                break;
            }
            i++;
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

        lines = SwingUtils.countLines(saveFileFullPath.getPath());
        System.out.println(String.format("%s is done. total %d flows ",fileName,lines));
        System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d",nTotal,nValid,nDiscarded));
        String countFileName =fileName+"_count" + FlowMgr.FLOW_SUFFIX+FlowMgr.CSV_SUFFIX;
        String count_header = "count";
        int average=nValid/10;
        for(int l=0; l<=15; l++) {
        	
        	int rand=(int) (Math.random() * (5));
        	int count=average;
        	
            if(l%2==0)
            {
            	count=(count>average)?average-rand:average;
            }
            else{
            	count=average+rand;
            }
          List<String> FlowCountList = new ArrayList<String>();
          String packetCountRow;
           packetCountRow =String.valueOf(count);
               FlowCountList.add(packetCountRow);
              csvWriterThread.execute(new InsertCsvRow(count_header, FlowCountList,outPath,countFileName));

        }

        System.out.println(DividingLine);

        return (int) lines;

    }





    static class FlowListener implements FlowGenListener {

        private String fileName;
        private String outPath;
        private int counter;

        private long cnt;

        public FlowListener(String fileName, String outPath,int counter) {
            this.fileName = fileName;
            this.outPath = outPath;
            this.counter=counter;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, fileName + FlowMgr.FLOW_SUFFIX+counter+FlowMgr.CSV_SUFFIX);
            count++;
            String console = String.format("%s -> %d flows \r", fileName,cnt);
        }
    }

}