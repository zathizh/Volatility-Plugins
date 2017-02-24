import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.plugins.filescan as filescan

class HidProc(common.AbstractWindowsCommand):
    """This is the plugin to search for the hidden processes"""    
    def calculate(self):
        # setting the address space
        addr_space = utils.load_as(self._config)

        # initalte pslist and get the results 
        pl = tasks.pslist(addr_space)
        # initialte psscan and get the results
        ps = filescan.PSScan(self._config).calculate()


        # list to store pid s
        pids = []

        #store the pid s of processes
        for process in pl:
            pids.append(int(process.UniqueProcessId))


        # compare the results from psscan and pslist, yield the hidden process    
        for process in ps:
            if int(process.UniqueProcessId) not in pids:
                yield process


    # render_text function uses tooutput the results
    def render_text(self, outfd, data):

        # print the header informations 
        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('Name', '<20'),
                                  ('PID', '<6'),
                                  ('PPID', '<6'),
                                  ('PDB', '[addrpad]'),
                                  ('Time created', '30'),
                                  ('Time exited', '30'),
                                  ])
        # output the informations of processes
        for process in data:
            self.table_row(outfd,
                           process.obj_offset,
                           process.ImageFileName,
                           process.UniqueProcessId,
                           process.InheritedFromUniqueProcessId,
                           process.Pcb.DirectoryTableBase,
                           process.CreateTime or '',
                           process.ExitTime or '',)
