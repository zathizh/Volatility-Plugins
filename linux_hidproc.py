import volatility.obj as obj
import volatility.utils as utils

import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.psscan as linux_psscan
import volatility.plugins.linux.common as linux_common

class linux_hidproc(linux_common.AbstractLinuxCommand):
    """This is plugin to search hidden linux processes"""
    def calculate(self):
        linux_common.set_plugin_members(self)
        phys_addr_space = utils.load_as(self._config, astype = 'physical')

        pl = linux_pslist.linux_pslist(self._config).calculate()
        ps = linux_psscan.linux_psscan(self._config).calculate()

        pids = []

        for process in pl:
            pids.append(int(process.pid))

        for process in ps:
            if int(process.pid) not in pids:
                start_time = process.get_task_start_time()
                if start_time == None:
                    start_time = ""

                if process.mm.pgd == None:
                    dtb = process.mm.pgd
                else:
                    dtb = self.addr_space.vtop(process.mm.pgd) or process.mm.pgd
                    
                yield process, start_time, dtb

    # render_text function uses tooutput the results
    def render_text(self, outfd, data):
        # print the header informations
        self.table_header(outfd, [('Offset(V)', '[addrpad]'),
                                  ('Name', '<20'),
                                  ('PID', '>6'),
                                  ("DTB", "[addrpad]"),
                                  ("Start Time", ""),
                                  ])
        
        # output the informations of processes
        for process, start_time, dtb in data:
            self.table_row(outfd,
                           process,
                           process.comm,
                           process.pid,
                           dtb,
                           str(start_time),
                           )
            
