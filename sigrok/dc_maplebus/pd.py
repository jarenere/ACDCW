import sigrokdecode as srd
import math


class SamplerateError(Exception):
    pass

class Decoder(srd.Decoder):
    api_version = 2
    id = 'dc_maplebus'
    name = 'dc maple bus'
    longname = 'Dreamcast maple bus controller'
    desc = 'Two-wire, serial bus, mix clock and data'
    license = 'gplv3+'
    inputs = ['logic']
    outputs = ['maple']
    channels = (
        {'id': 'sd0', 'name': 'SD0',
         'desc': 'Serial data(phase2) and clock (phase1)'},
        {'id': 'sd1', 'name': 'SD1',
         'desc': 'Serial data(phase1) and clock (phase2)'},
    )

    annotations = (
        ('bit', 'bit'),
        ('bit', 'bit'),
        ('sync', 'Sync'),
        ('msg', 'Message'),
        ('eom', 'End Of Message'),
        ('idle', 'IDLE'),
        ('packet', 'Packet'),
        ('checksum', 'CheckSum'),
        ('warnings', 'Warnings'),

    )
    annotation_rows = (
        ('bits', 'Bits sd0', (0,)),
        ('bits', 'Bits sd1', (1,)),
        ('fields', 'Fields', (2, 3, 4, 5)),
        ('packets', 'Packets', (6, 7)),
        ('warnings', 'Warnings', (8,)),
    )

    def __init__(self, **kwargs):
        self.samplerate = None
        self.state = 'IDLE'
        self.old_sd0 = 1
        self.old_sd1 = 1
        self.n_flank_sync = None  # number flank down to sync
        self.ss = None
        self.es_message = None
        self.ss_message = None
        self.ss_warning = None
        self.data0 = None
        self.data1 = None
        self.ss_field = None
        self.stream_bits = ''
        self.bits = ''
        # packet 4 bytes, MSB first.But the order of the four bytes is reversed
        self.packet = []
        self.byte = None
        self.ss_packet = None

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def putb(self, data):
        self.put(self.ss_bit, self.samplenum, self.out_ann, data)

    def putx(self, data):
        # use to put sync and eof
        self.put(self.ss_field, self.samplenum, self.out_ann, data)

    def putm(self, data):
        # use to put message
        self.put(self.ss_message, self.es_phase2, self.out_ann, data)

    def put_packet(self, data):
        self.put(self.ss_packet, self.es_phase2, self.out_ann, data)

    def putp(self, data):
        self.put(self.ss, self.es, self.out_python, data)

    # DREAMCAAAAASSSTT
    # def start_sync(self, sd1, sd2):
    #     # Start sync when d1 = low and d2 = high
    #     if sd1 == 0 and sd2 == 1:
    #         # reset count sync flank
    #         self.n_sync_flank = 0
    #         self.state = 'START SYNC'
    #         self.ss = self.samplenum

    # def synced(self, sd1, sd2):
    #     if sd2 == 0:
    #         self.n_sync_flank += 1
    #     if self.n_sync_flank == 4:
    #         self.state = 'END SYNC'
    #         self.es = self.samplenum

    # def start_phase1(self, sd1, sd2):
    #     # Start phase1 when sd1 = high and sd2 = low
    #     if sd1 == 1 and sd2 == 0:
    #         if self.state == "END SYNC":
    #             self.es = self.samplenum
    #             self.putx([0, ["sync"]])
    #         if self.state in ('START PHASE1', 'END PHASE2'):  # finished phase2
    #             self.es_phase = self.samplenum
    #             self.putx_phase([0, [str(self.data1)]])

    #         self.ss_phase = self.samplenum
    #         self.state = 'START PHASE1'

    # def get_sd2(self, sd1, sd2):
    #     # when sd1 = 0, sd2 == data
    #     if sd1 == 0:
    #         # print("data" + str(sd2))
    #         # sd2 =1,->serial data prepared for phase2
    #         self.data2 = sd2
    #         if sd1 == 0 and sd2 == 1:
    #             self.state = 'START PHASE2'
    #         else:
    #             self.state = 'END PHASE1'

    # def start_phase2(self, sd1, sd2):
    #     if sd1 == 0 and sd2 == 1:
    #         self.state = 'START PHASE2'
    #         # draw bit phase1
    #         self.es_phase = self.samplenum
    #         self.putx_phase([0, [str(self.data2)]])
    #         self.ss_phase = self.samplenum
    #     # if sd1 high, sd2 low-> sequence end
    #     if sd1 == 1 and sd2 == 0:
    #         self.state = 'END OF MESSAGE'

    # def get_sd1(self, sd1, sd2):
    #     # when sd2 = 0, sd1 == data
    #     if sd2 == 0:
    #         # print("data" + str(sd1))
    #         # serial data prepared for phase 1 or end
    #         self.data1 = sd1
    #         if sd2 == 0 and sd1 == 1:
    #             self.state = 'START PHASE1'
    #         else:
    #             self.state = 'END PHASE2'

    # def end_of_message(self, sd1, sd2):
    #     # already detected first part "end sequence"
    #     if sd1 == 0 and sd2 == 0:
    #         None
    #     if sd1 == 1 and sd2 == 0:
    #         None
    #     if sd1 == 1 and sd2 == 1:
    #         self.state = 'IDLE'



    def is_byte(self):
        if len(self.bits) == 8:
            self.packet.insert(0, '{:02X}'.format(int(self.bits, 2)))
            self.is_packet()
            self.bits = ''
            return True
        return False


    def is_packet(self):
        if len(self.packet) == 4:
            ''.join(self.packet)
            self.put_packet([6, ['%s : %s' % ('Packet', ','.join(self.packet)),
                            '%s : %s' % ('pck', ','.join(self.packet)),
                             ''.join(self.packet)]])
            self.packet = []
            self.ss_packet = self.samplenum
            return True
        return False

    def put_checksum(self):
        def calculate_xor(bits):
            l = (math.ceil(len(bits)/8)) * 2
            s2 = '%%0%iX' % l
            hexadecimals = s2 % int(bits, 2)
            xor = 0
            for i in range(int((len(hexadecimals)-2)/2)):
                xor = xor ^ int(hexadecimals[2*i:2*i+2], 16)
            return xor == int(hexadecimals[-2:], 16)

        # Put checksum and check
        checksum = self.packet[0]
        self.put_packet([7, ['%s : %s' % ('CheckSum', checksum),
                             '%s : %s' % ('CKS', checksum),
                             '%s' % (checksum)]])
        if not calculate_xor(self.stream_bits[:-1]):
            put_packet([8, ['Bad CRC']])

    def is_start_sync(self, sd0, sd1):
        if sd0 == 0 and sd1 == 1:
            # reset count sync flank
            self.n_flank_sync = 0
            self.state = 'START_SYNC'
            self.ss_field = self.samplenum
            return True
        elif not(sd0 == 1 and sd1 == 1):
            self.ss_warning = self.samplenum
        return False

    def is_finish_sync(self, sd0, sd1):
        if sd0 == 1 and sd1 == 0 and self.n_flank_sync == 4:
            self.state = 'START_PHASE1'
            return True
        if sd1 == 0:
            self.n_flank_sync += 1
        return False

    def is_get_data0(self, sd0, sd1):
        # phase1 start when sd0 == high and sd1 == low
        # finish phase1 when sd0 == low and  sd1 == high
        # when  sd0 = low -> sd1 == data
        if sd0 == 0:
            self.data0 = sd1
            self.stream_bits = self.stream_bits + str(sd1)
            self.bits = self.bits + str(sd1)
            return True
        return False

    def is_finish_phase1(self, sd0, sd1):
        if sd0 == 0 and sd1 == 1:
            self.state = 'START_PHASE2'
            self.putb([1, [str(self.data0)]])
            self.ss_bit = self.samplenum
            return True
        elif sd0 == 0 and sd1 == 0:  # data0 == 0
            self.state = 'PHASE1'
            return False
        elif sd0 == 1 and sd1 == 0:
            self.state = 'END_OF_MESSAGE'
            return True

    def is_get_data1(self, sd0, sd1):
        # phase2 start when sd0 == low and sd1 == high
        # finish phase2 when sd0 == high and  sd1 == low
        # when  sd1 = low -> sd0 == data
        if sd1 == 0:
            self.data1 = sd0
            self.stream_bits = self.stream_bits + str(sd0)
            self.bits = self.bits + str(sd0)
            return True
        return False

    def is_finish_phase2(self, sd0, sd1):
        if sd0 == 1 and sd1 == 0:
            self.state = 'START_PHASE1'
            self.putb([0, [str(self.data1)]])
            self.ss_bit = self.samplenum
            self.ss_field = self.samplenum  # can star eom
            self.es_phase2 = self.samplenum  # can finish message
            self.is_byte()
            return True
        else:
            self.state = 'PHASE2'
            return False

    def is_finish_end_of_message(self, sd0, sd1):
            if sd0 == 1 and sd1 == 0:
                return False
            if sd0 == 0 and sd1 == 0:
                return False
            if sd0 == 1 and sd0 == 1:
                self.state = 'IDLE'
                # Delete all load bit because is part of eom
                bits = self.stream_bits[:-1]
                print(len(bits))
                print(bits)
                print((math.ceil(len(bits)/8)) * 2)
                l = (math.ceil(len(bits)/8)) * 2
                s1 = '%%s : %%0%iX' % l
                s2 = '%%0%iX' % l
                self.putm([3, [s1 % ('Message', int(bits, 2)),
                               s1 % ('Msg', int(bits, 2)),
                               s1 % ('M', int(bits, 2)),
                               s2 % int(bits, 2)]])
                self.putx([4, ['End of message', 'EOM', 'E']])
                self.put_checksum()
                self.stream_bits = ''
                self.bits = ''
                self.packet = []
                return True

    def decode(self, ss, es, data):
        if not self.samplerate:
            raise SamplerateError('Cannot decode without samplerate.')

        for self.samplenum, (sd0, sd1) in data:

            if self.old_sd0 == sd0 and self.old_sd1 == sd1:
                continue

            self.old_sd0 = sd0
            self.old_sd1 = sd1

            if self.state == 'IDLE':
                self.is_start_sync(sd0, sd1)

            elif self.state == 'START_SYNC':
                if self.is_finish_sync(sd0, sd1):
                    self.putx([2, ['Sync', 'S']])
                    self.ss_bit = self.ss_field = self.ss_message \
                                = self.ss_packet = self.samplenum

            elif self.state == 'START_PHASE1':
                if self.is_get_data0(sd0, sd1):
                    self.is_finish_phase1(sd0, sd1)

            elif self.state == 'PHASE1':
                self.is_finish_phase1(sd0, sd1)

            elif self.state == 'START_PHASE2':
                if self.is_get_data1(sd0, sd1):
                    self.is_finish_phase2(sd0, sd1)

            elif self.state == 'PHASE2':
                self.is_finish_phase2(sd0, sd1)

            elif self.state == 'END_OF_MESSAGE':
                self.is_finish_end_of_message(sd0, sd1)







        # for self.samplenum, (sd1, sd2) in data:

        #     # Ignore identical samples early on (for performance reasons).
        #     if self.oldsd1 == sd1 and self.oldsd2 == sd2:
        #         continue

        #     self.oldsd1, self.oldsd2 = sd1, sd2

        #     # State machine
        #     # IDENTIFICAR cuando una fase termina en alto o termina en bajo
        #     # ya que el siguiente estado puede ser disitinto,ejemplo:
        #     # fin fase1, sd1 bajo, sd2 alto ya esta preparado para fase2, por
        #     # lo que como quito los pins repetidos, start_phase2 nunca se
        #     # ejecuta
        #     if self.state == 'IDLE':
        #         self.start_sync(sd1, sd2)

        #     elif self.state == 'START SYNC':
        #         self.synced(sd1, sd2)

        #     elif self.state in ('END SYNC', 'END PHASE2'):
        #         self.start_phase1(sd1, sd2)

        #     elif self.state == 'START PHASE1':
        #         self.get_sd2(sd1, sd2)

        #     elif self.state == 'END PHASE1':
        #         self.start_phase2(sd1, sd2)

        #     elif self.state == 'START PHASE2':
        #         self.get_sd1(sd1, sd2)

        #     elif self.state == 'END OF MESSAGE':
        #         self.end_of_message(sd1, sd2)
