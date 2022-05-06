import enum
import json

import orm_sqlite
import pandas as pd
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
import sqlalchemy

Base=declarative_base()
class FlowEnum(enum.Enum):
    fid="Flow ID"
    src_ip="Src IP"
    src_port="Src Port"
    dst_ip="Dst IP"
    dst_pot="Dst Port"
    prot="Protocol"
    tstp="Timestamp"
    fl_dur="Flow Duration"
    tot_fw_pkt="Tot Fwd Pkts"
    tot_bw_pkt="Tot Bwd Pkts"
    tot_l_fw_pkt="TotLen Fwd Pkts"
    tot_l_bw_pkt="TotLen Bwd Pkts"
    fw_pkt_l_max="Fwd Pkt Len Max"
    fw_pkt_l_min="Fwd Pkt Len Min"
    fw_pkt_l_avg="Fwd Pkt Len Mean"
    fw_pkt_l_std="Fwd Pkt Len Std"
    bw_pkt_l_max="Bwd Pkt Len Max"
    bw_pkt_l_min="Bwd Pkt Len Min"
    bw_pkt_l_avg="Bwd Pkt Len Mean"
    bw_pkt_l_std="Bwd Pkt Len Std"
    fl_byt_s="Flow Byts/s"
    fl_pkt_s="Flow Pkts/s"
    fl_iat_avg="Flow IAT Mean"
    fl_iat_std="Flow IAT Std"
    fl_iat_max="Flow IAT Max"
    fl_iat_min="Flow IAT Min"
    fw_iat_tot="Fwd IAT Tot"
    fw_iat_avg="Fwd IAT Mean"
    fw_iat_std="Fwd IAT Std"
    fw_iat_max="Fwd IAT Max"
    fw_iat_min="Fwd IAT Min"
    bw_iat_tot="Bwd IAT Tot"
    bw_iat_avg="Bwd IAT Mean"
    bw_iat_std="Bwd IAT Std"
    bw_iat_max="Bwd IAT Max"
    bw_iat_min="Bwd IAT Min"
    fw_psh_flag="Fwd PSH Flags"
    bw_psh_flag="Bwd PSH Flags"
    fw_urg_flag="Fwd URG Flags"
    bw_urg_flag="Bwd URG Flags"
    fw_hdr_len="Fwd Header Len"
    bw_hdr_len="Bwd Header Len"
    fw_pkt_s="Fwd Pkts/s"
    bw_pkt_s="Bwd Pkts/s"
    pkt_len_min="Pkt Len Min"
    pkt_len_max="Pkt Len Max"
    pkt_len_avg="Pkt Len Mean"
    pkt_len_std="Pkt Len Std"
    pkt_len_var="Pkt Len Var"
    fin_cnt="FIN Flag Cnt"
    syn_cnt="SYN Flag Cnt"
    rst_cnt="RST Flag Cnt"
    pst_cnt="PSH Flag Cnt"
    ack_cnt="ACK Flag Cnt"
    urg_cnt="URG Flag Cnt"
    cwe_cnt="CWE Flag Count"
    ece_cnt="ECE Flag Cnt"
    down_up_ratio="Down/Up Ratio"
    pkt_size_avg="Pkt Size Avg"
    fw_seg_avg="Fwd Seg Size Avg"
    bw_seg_avg="Bwd Seg Size Avg"
    fw_byt_blk_avg="Fwd Byts/b Avg"
    fw_pkt_blk_avg="Fwd Pkts/b Avg"
    fw_blk_rate_avg="Fwd Blk Rate Avg"
    bw_byt_blk_avg="Bwd Byts/b Avg"
    bw_pkt_blk_avg="Bwd Pkts/b Avg"
    bw_blk_rate_avg="Bwd Blk Rate Avg"
    subfl_fw_pkt="Subflow Fwd Pkts"
    subfl_fw_byt="Subflow Fwd Byts"
    subfl_bw_pkt="Subflow Bwd Pkts"
    subfl_bw_byt="Subflow Bwd Byts"
    fw_win_byt="Init Fwd Win Byts"
    bw_win_byt="Init Bwd Win Byts"
    Fw_act_pkt="Fwd Act Data Pkts"
    fw_seg_min="Fwd Seg Size Min"
    atv_avg="Active Mean"
    atv_std="Active Std"
    atv_max="Active Max"
    atv_min="Active Min"
    idl_avg="Idle Mean"
    idl_std="Idle Std"
    idl_max="Idle Max"
    idl_min="Idle Min"
    label="Label"


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


#
#
# class Flow(orm_sqlite.Model):
#     id=orm_sqlite.IntegerField(primary_key=True)
#     fid=orm_sqlite.StringField()
#     src_ip=orm_sqlite.StringField()
#     src_port=orm_sqlite.StringField()
#     dst_ip=orm_sqlite.StringField()
#     dst_pot=orm_sqlite.StringField()
#     prot=orm_sqlite.StringField()
#     tstp=orm_sqlite.StringField()
#     fl_dur=orm_sqlite.StringField()
#     tot_fw_pkt=orm_sqlite.StringField()
#     tot_bw_pkt=orm_sqlite.StringField()
#     tot_l_fw_pkt=orm_sqlite.StringField()
#     tot_l_bw_pkt=orm_sqlite.StringField()
#     fw_pkt_l_max=orm_sqlite.StringField()
#     fw_pkt_l_min=orm_sqlite.StringField()
#     fw_pkt_l_avg=orm_sqlite.StringField()
#     fw_pkt_l_std=orm_sqlite.StringField()
#     bw_pkt_l_max=orm_sqlite.StringField()
#     bw_pkt_l_min=orm_sqlite.StringField()
#     bw_pkt_l_avg=orm_sqlite.StringField()
#     bw_pkt_l_std=orm_sqlite.StringField()
#     fl_byt_s=orm_sqlite.StringField()
#     fl_pkt_s=orm_sqlite.StringField()
#     fl_iat_avg=orm_sqlite.StringField()
#     fl_iat_std=orm_sqlite.StringField()
#     fl_iat_max=orm_sqlite.StringField()
#     fl_iat_min=orm_sqlite.StringField()
#     fw_iat_tot=orm_sqlite.StringField()
#     fw_iat_avg=orm_sqlite.StringField()
#     fw_iat_std=orm_sqlite.StringField()
#     fw_iat_max=orm_sqlite.StringField()
#     fw_iat_min=orm_sqlite.StringField()
#     bw_iat_tot=orm_sqlite.StringField()
#     bw_iat_avg=orm_sqlite.StringField()
#     bw_iat_std=orm_sqlite.StringField()
#     bw_iat_max=orm_sqlite.StringField()
#     bw_iat_min=orm_sqlite.StringField()
#     fw_psh_flag=orm_sqlite.StringField()
#     bw_psh_flag=orm_sqlite.StringField()
#     fw_urg_flag=orm_sqlite.StringField()
#     bw_urg_flag=orm_sqlite.StringField()
#     fw_hdr_len=orm_sqlite.StringField()
#     bw_hdr_len=orm_sqlite.StringField()
#     fw_pkt_s= orm_sqlite.StringField()
#     bw_pkt_s= orm_sqlite.StringField()
#     pkt_len_min= orm_sqlite.StringField()
#     pkt_len_max= orm_sqlite.StringField()
#     pkt_len_avg= orm_sqlite.StringField()
#     pkt_len_std= orm_sqlite.StringField()
#     pkt_len_var= orm_sqlite.StringField()
#     fin_cnt= orm_sqlite.StringField()
#     syn_cnt= orm_sqlite.StringField()
#     rst_cnt= orm_sqlite.StringField()
#     pst_cnt= orm_sqlite.StringField()
#     ack_cnt= orm_sqlite.StringField()
#     urg_cnt= orm_sqlite.StringField()
#     cwe_cnt= orm_sqlite.StringField()
#     ece_cnt= orm_sqlite.StringField()
#     down_up_ratio= orm_sqlite.StringField()
#     pkt_size_avg= orm_sqlite.StringField()
#     fw_seg_avg= orm_sqlite.StringField()
#     bw_seg_avg= orm_sqlite.StringField()
#     fw_byt_blk_avg= orm_sqlite.StringField()
#     fw_pkt_blk_avg= orm_sqlite.StringField()
#     fw_blk_rate_avg= orm_sqlite.StringField()
#     bw_byt_blk_avg= orm_sqlite.StringField()
#     bw_pkt_blk_avg= orm_sqlite.StringField()
#     bw_blk_rate_avg= orm_sqlite.StringField()
#     subfl_fw_pkt= orm_sqlite.StringField()
#     subfl_fw_byt=  orm_sqlite.StringField()
#     subfl_bw_pkt = orm_sqlite.StringField()
#     subfl_bw_byt=orm_sqlite.StringField()
#     fw_win_byt=orm_sqlite.StringField()
#     bw_win_byt=orm_sqlite.StringField()
#     Fw_act_pkt=orm_sqlite.StringField()
#     fw_seg_min=orm_sqlite.StringField()
#     atv_avg=orm_sqlite.StringField()
#     atv_std=orm_sqlite.StringField()
#     atv_max=orm_sqlite.StringField()
#     atv_min=orm_sqlite.StringField()
#     idl_avg=orm_sqlite.StringField()
#     idl_std=orm_sqlite.StringField()
#     idl_max=orm_sqlite.StringField()
#     idl_min=orm_sqlite.StringField()
#     label=orm_sqlite.StringField()
#
#

def get_packets():
    filepath="packets.csv"
    csv_file = pd.DataFrame(pd.read_csv(filepath, sep=",", header=0, index_col=False,))
    packets = csv_file.to_json(orient="records", date_format="epoch", double_precision=10, force_ascii=True,
                               date_unit="ms", default_handler=None)
    packet_dict=csv_file.to_dict()
    values=list(packet_dict.values())
    print(len(values[0]))
    dic_len=len(values[0])
    flow_list = []
    engine = create_engine("sqlite:///../Flow.db", echo=True, future=True)
    Base.metadata.create_all(engine)

    Session=sessionmaker(bind=engine)
    session=Session()
    stmt=session.query(Flow).order_by(Flow.id.desc()).limit(10)

    for s in stmt:
        str=json.dumps(s.__dict__)
        print(str)




    #
    # with Session(engine) as session:
    #     if dic_len >= 0:
    #
    #         for i in range(0,dic_len):
    #             flow =Flow()
    #             # flow['fid'] = values[0][i]
    #             # flow['src_ip'] = values[1][i]
    #             # flow['src_port'] = values[2][i]
    #             # flow['dst_ip'] = values[3][i]
    #             # flow['dst_pot'] = values[4][i]
    #             # flow['prot'] = values[5][i]
    #             # flow['tstp'] = values[6][i]
    #             # flow['fl_dur'] = values[7][i]
    #             # flow['tot_fw_pkt'] = values[8][i]
    #             # flow['tot_bw_pkt'] = values[9][i]
    #             # flow['tot_l_fw_pkt'] = values[10][i]
    #             # flow['tot_l_bw_pkt'] = values[11][i]
    #             # flow['fw_pkt_l_max'] = values[12][i]
    #             # flow['fw_pkt_l_min'] = values[13][i]
    #             # flow['fw_pkt_l_avg'] = values[14][i]
    #             # flow['fw_pkt_l_std'] = values[15][i]
    #             # flow['bw_pkt_l_max'] = values[16][i]
    #             # flow['bw_pkt_l_min'] = values[17][i]
    #             # flow['bw_pkt_l_avg'] = values[18][i]
    #             # flow['bw_pkt_l_std'] = values[19][i]
    #             # flow['fl_byt_s'] = values[20][i]
    #             # flow['fl_pkt_s'] = values[21][i]
    #             # flow['fl_iat_avg'] = values[22][i]
    #             # flow['fl_iat_std'] = values[23][i]
    #             # flow['fl_iat_max'] = values[24][i]
    #             # flow['fl_iat_min'] = values[25][i]
    #             # flow['fw_iat_tot'] = values[26][i]
    #             # flow['fw_iat_avg'] = values[27][i]
    #             # flow['fw_iat_std'] = values[28][i]
    #             # flow['fw_iat_max'] = values[29][i]
    #             # flow['fw_iat_min'] = values[30][i]
    #             # flow['bw_iat_tot'] = values[31][i]
    #             # flow['bw_iat_avg'] = values[32][i]
    #             # flow['bw_iat_std'] = values[33][i]
    #             # flow['bw_iat_max'] = values[34][i]
    #             # flow['bw_iat_min'] = values[35][i]
    #             # flow['fw_psh_flag'] = values[36][i]
    #             # flow['bw_psh_flag'] = values[37][i]
    #             # flow['fw_urg_flag'] = values[38][i]
    #             # flow['bw_urg_flag'] = values[39][i]
    #             # flow['fw_hdr_len'] = values[40][i]
    #             # flow['bw_hdr_len'] = values[41][i]
    #             # flow['fw_pkt_s'] = values[42][i]
    #             # flow['bw_pkt_s'] = values[43][i]
    #             # flow['pkt_len_min'] = values[44][i]
    #             # flow['pkt_len_max'] = values[45][i]
    #             # flow['pkt_len_avg'] = values[46][i]
    #             # flow['pkt_len_std'] = values[47][i]
    #             # flow['pkt_len_var'] = values[48][i]
    #             # flow['fin_cnt'] = values[49][i]
    #             # flow['syn_cnt'] = values[50][i]
    #             # flow['rst_cnt'] = values[51][i]
    #             # flow['pst_cnt'] = values[52][i]
    #             # flow['ack_cnt'] = values[53][i]
    #             # flow['urg_cnt'] = values[54][i]
    #             # flow['cwe_cnt'] = values[55][i]
    #             # flow['ece_cnt'] = values[56][i]
    #             # flow['down_up_ratio'] = values[57][i]
    #             # flow['pkt_size_avg'] = values[58][i]
    #             # flow['fw_seg_avg'] = values[59][i]
    #             # flow['bw_seg_avg'] = values[60][i]
    #             # flow['fw_byt_blk_avg'] = values[61][i]
    #             # flow['fw_pkt_blk_avg'] = values[62][i]
    #             # flow['fw_blk_rate_avg'] = values[63][i]
    #             # flow['bw_byt_blk_avg'] = values[64][i]
    #             # flow['bw_pkt_blk_avg'] = values[65][i]
    #             # flow['bw_blk_rate_avg'] = values[66][i]
    #             # flow['subfl_fw_pkt'] = values[67][i]
    #             # flow['subfl_fw_byt'] = values[68][i]
    #             # flow['subfl_bw_pkt'] = values[69][i]
    #             # flow['subfl_bw_byt'] = values[70][i]
    #             # flow['fw_win_byt'] = values[71][i]
    #             # flow['bw_win_byt'] = values[72][i]
    #             # flow['Fw_act_pkt'] = values[73][i]
    #             # flow['fw_seg_min'] = values[74][i]
    #             # flow['atv_avg'] = values[75][i]
    #             # flow['atv_std'] = values[76][i]
    #             # flow['atv_max'] = values[77][i]
    #             # flow['atv_min'] = values[78][i]
    #             # flow['idl_avg'] = values[79][i]
    #             # flow['idl_std'] = values[80][i]
    #             # flow['idl_max'] = values[81][i]
    #             # flow['idl_min'] = values[82][i]
    #             # flow['label'] = values[83][i]
    #             # flow.save()

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






if __name__=="__main__":
    get_packets()




