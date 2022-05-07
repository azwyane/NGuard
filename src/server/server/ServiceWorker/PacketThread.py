import pathlib
import threading
import pandas as pd
import os
import re
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer


Base = declarative_base()


class Flow(Base):
    __tablename__="flow"
    id=Column(Integer,primary_key=True)
    fid=Column(String(60))
    src_ip=Column(String(60))
    src_port=Column(String(60))
    dst_ip=Column(String(60))
    dst_pot=Column(String(60))
    prot=Column(String(60))
    tstp=Column(String(60))
    fl_dur=Column(String(60))
    tot_fw_pkt=Column(String(60))
    tot_bw_pkt=Column(String(60))
    tot_l_fw_pkt=Column(String(60))
    tot_l_bw_pkt=Column(String(60))
    fw_pkt_l_max=Column(String(60))
    fw_pkt_l_min=Column(String(60))
    fw_pkt_l_avg=Column(String(60))
    fw_pkt_l_std=Column(String(60))
    bw_pkt_l_max=Column(String(60))
    bw_pkt_l_min=Column(String(60))
    bw_pkt_l_avg=Column(String(60))
    bw_pkt_l_std=Column(String(60))
    fl_byt_s=Column(String(60))
    fl_pkt_s=Column(String(60))
    fl_iat_avg=Column(String(60))
    fl_iat_std=Column(String(60))
    fl_iat_max=Column(String(60))
    fl_iat_min=Column(String(60))
    fw_iat_tot=Column(String(60))
    fw_iat_avg=Column(String(60))
    fw_iat_std=Column(String(60))
    fw_iat_max=Column(String(60))
    fw_iat_min=Column(String(60))
    bw_iat_tot=Column(String(60))
    bw_iat_avg=Column(String(60))
    bw_iat_std=Column(String(60))
    bw_iat_max=Column(String(60))
    bw_iat_min=Column(String(60))
    fw_psh_flag=Column(String(60))
    bw_psh_flag=Column(String(60))
    fw_urg_flag=Column(String(60))
    bw_urg_flag=Column(String(60))
    fw_hdr_len=Column(String(60))
    bw_hdr_len=Column(String(60))
    fw_pkt_s= Column(String(60))
    bw_pkt_s= Column(String(60))
    pkt_len_min= Column(String(60))
    pkt_len_max= Column(String(60))
    pkt_len_avg= Column(String(60))
    pkt_len_std= Column(String(60))
    pkt_len_var= Column(String(60))
    fin_cnt= Column(String(60))
    syn_cnt= Column(String(60))
    rst_cnt= Column(String(60))
    pst_cnt= Column(String(60))
    ack_cnt= Column(String(60))
    urg_cnt= Column(String(60))
    cwe_cnt= Column(String(60))
    ece_cnt= Column(String(60))
    down_up_ratio= Column(String(60))
    pkt_size_avg= Column(String(60))
    fw_seg_avg= Column(String(60))
    bw_seg_avg= Column(String(60))
    fw_byt_blk_avg= Column(String(60))
    fw_pkt_blk_avg= Column(String(60))
    fw_blk_rate_avg= Column(String(60))
    bw_byt_blk_avg= Column(String(60))
    bw_pkt_blk_avg= Column(String(60))
    bw_blk_rate_avg= Column(String(60))
    subfl_fw_pkt= Column(String(60))
    subfl_fw_byt=  Column(String(60))
    subfl_bw_pkt = Column(String(60))
    subfl_bw_byt=Column(String(60))
    fw_win_byt=Column(String(60))
    bw_win_byt=Column(String(60))
    Fw_act_pkt=Column(String(60))
    fw_seg_min=Column(String(60))
    atv_avg=Column(String(60))
    atv_std=Column(String(60))
    atv_max=Column(String(60))
    atv_min=Column(String(60))
    idl_avg=Column(String(60))
    idl_std=Column(String(60))
    idl_max=Column(String(60))
    idl_min=Column(String(60))
    label=Column(String(60))


class PacketThread(threading.Thread):
    def __init__(self, heartbeat,flow_directory,flow_db_path):
        threading.Thread.__init__(self)
        self.heartbeat=int(heartbeat)
        self.flow_directory=flow_directory
        self.flow_db_path=flow_db_path


    def run(self):
        print("packet listening thread started")
        Base = declarative_base()
        engine = create_engine(f"sqlite:///{self.flow_db_path}", echo=True, future=True)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        dt = datetime.now()
        FILE_PATH = self.flow_directory
        file_initials=dt.strftime('%Y-%m-%d')
        dir_list = os.listdir(FILE_PATH+file_initials)
        counter=1
        for dir in dir_list:
            print(dir)
            if(file_initials+"_Flow" in dir):

                count = int(re.search(r'\d+', dir).group())
                if(count>=counter):
                    counter=count
        while(True):
            filepath = f"{FILE_PATH}{dt.strftime('%Y-%m-%d')}/{dt.strftime('%Y-%m-%d')}_Flow{counter}.csv"
            if pathlib.Path(filepath).is_file():
                csv_file = pd.DataFrame(pd.read_csv(filepath, sep=",", header=0, index_col=False, ))
                packets = csv_file.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,
                                           date_unit="ms", default_handler=None)
                packet_dict = csv_file.to_dict()
                values = list(packet_dict.values())
                # stmt = session.query(Flow).order_by(Flow.id.desc()).limit(10)


    def storePacket(self, values, session):
        dict_len=len(values[0])
        if dict_len > 0:
            for i in range(0,dict_len):
                data_exists= session.query(Flow.query.filter(Flow.fid == values[0][i]).exists()).scalar()
                if data_exists==False:
                    flow=Flow()
                    flow.fid = values[0][i]
                    flow.src_ip = values[1][i]
                    flow.src_port = values[2][i]
                    flow.dst_ip = values[3][i]
                    flow.dst_pot = values[4][i]
                    flow.prot = values[5][i]
                    flow.tstp = values[6][i]
                    flow.fl_dur = values[7][i]
                    flow.tot_fw_pkt = values[8][i]
                    flow.tot_bw_pkt = values[9][i]
                    flow.tot_l_fw_pkt = values[10][i]
                    flow.tot_l_bw_pkt = values[11][i]
                    flow.fw_pkt_l_max = values[12][i]
                    flow.fw_pkt_l_min = values[13][i]
                    flow.fw_pkt_l_avg = values[14][i]
                    flow.fw_pkt_l_std = values[15][i]
                    flow.bw_pkt_l_max = values[16][i]
                    flow.bw_pkt_l_min = values[17][i]
                    flow.bw_pkt_l_avg = values[18][i]
                    flow.bw_pkt_l_std = values[19][i]
                    flow.fl_byt_s = values[20][i]
                    flow.fl_pkt_s = values[21][i]
                    flow.fl_iat_avg = values[22][i]
                    flow.fl_iat_std = values[23][i]
                    flow.fl_iat_max = values[24][i]
                    flow.fl_iat_min = values[25][i]
                    flow.fw_iat_tot = values[26][i]
                    flow.fw_iat_avg = values[27][i]
                    flow.fw_iat_std = values[28][i]
                    flow.fw_iat_max = values[29][i]
                    flow.fw_iat_min = values[30][i]
                    flow.bw_iat_tot = values[31][i]
                    flow.bw_iat_avg = values[32][i]
                    flow.bw_iat_std = values[33][i]
                    flow.bw_iat_max = values[34][i]
                    flow.bw_iat_min = values[35][i]
                    flow.fw_psh_flag = values[36][i]
                    flow.bw_psh_flag = values[37][i]
                    flow.fw_urg_flag = values[38][i]
                    flow.bw_urg_flag = values[39][i]
                    flow.fw_hdr_len = values[40][i]
                    flow.bw_hdr_len = values[41][i]
                    flow.fw_pkt_s = values[42][i]
                    flow.bw_pkt_s = values[43][i]
                    flow.pkt_len_min = values[44][i]
                    flow.pkt_len_max = values[45][i]
                    flow.pkt_len_avg = values[46][i]
                    flow.pkt_len_std = values[47][i]
                    flow.pkt_len_var = values[48][i]
                    flow.fin_cnt = values[49][i]
                    flow.syn_cnt = values[50][i]
                    flow.rst_cnt = values[51][i]
                    flow.pst_cnt = values[52][i]
                    flow.ack_cnt = values[53][i]
                    flow.urg_cnt = values[54][i]
                    flow.cwe_cnt = values[55][i]
                    flow.ece_cnt = values[56][i]
                    flow.down_up_ratio = values[57][i]
                    flow.pkt_size_avg = values[58][i]
                    flow.fw_seg_avg = values[59][i]
                    flow.bw_seg_avg = values[60][i]
                    flow.fw_byt_blk_avg = values[61][i]
                    flow.fw_pkt_blk_avg = values[62][i]
                    flow.fw_blk_rate_avg = values[63][i]
                    flow.bw_byt_blk_avg = values[64][i]
                    flow.bw_pkt_blk_avg = values[65][i]
                    flow.bw_blk_rate_avg = values[66][i]
                    flow.subfl_fw_pkt = values[67][i]
                    flow.subfl_fw_byt = values[68][i]
                    flow.subfl_bw_pkt = values[69][i]
                    flow.subfl_bw_byt = values[70][i]
                    flow.fw_win_byt = values[71][i]
                    flow.bw_win_byt = values[72][i]
                    flow.Fw_act_pkt = values[73][i]
                    flow.fw_seg_min = values[74][i]
                    flow.atv_avg = values[75][i]
                    flow.atv_std = values[76][i]
                    flow.atv_max = values[77][i]
                    flow.atv_min = values[78][i]
                    flow.idl_avg = values[79][i]
                    flow.idl_std = values[80][i]
                    flow.idl_max = values[81][i]
                    flow.idl_min = values[82][i]
                    flow.label = values[83][i]

                    session.add_all([flow])
                    session.commit()

