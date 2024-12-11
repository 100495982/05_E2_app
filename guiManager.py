from rich.console import Console
from rich.table import Table
from rich.padding import Padding 

class GUIManager:
    def __init__(self):
        self.console = Console()
        self._width = int(self.console.width * 0.7)
        self._pad = (self.console.width - self._width) // 2


    def initial_options(self):
        self.console.print("[bold green]Bienvenido a MensajeriaPrivada[/bold green]", 
                           justify="center")
        initial_table = Table(width=self._width,
                              title="[green]Please choose an option: [/green]",
                              expand=True)
        initial_table.add_column("Option", style="cyan", justify="left")
        initial_table.add_column("Input", style="red", justify="center")
       
        initial_table.add_row("Register", "1")
        initial_table.add_row("Log in", "2")
        initial_table.add_row("Quit", "3")
        
        self.console.print(Padding(initial_table, (0, self._pad, 0, self._pad)))
        self.print_msg("Select an option (1, 2, 3): ")  
    
    
    def session_options(self):
        self.console.print(f"[green] Welcome back, it's good to see you again [/green]",
                           justify="center")
        session_table = Table(width=self._width,
                              title="[green]Please choose an option: [/green]",
                              expand=True)
        session_table.add_column("For action", style="cyan", justify="left")
        session_table.add_column("Type:", style="cyan", justify="left")
        
        session_table.add_row("Send a message to a registered user", "send")
        session_table.add_row("Read your messages", "read")
        session_table.add_row("Exit session", "exit")
        
        self.console.print(Padding(session_table, (0, self._pad, 0, self._pad)))
        self.print_msg("Please input action: ")  
    
    @staticmethod 
    def print_msg(msg: str, options=""):
        """ Funcion que toma un str y lo formatea a azul en italicas y centrado """
        console = Console()
        if options == "":
            console.print(f"[italic blue] {msg} [/italic blue]", justify="left")
        elif options == "bold": 
            console.print(f"[bold italic blue] {msg} [/bold italic blue]", justify="left")
        elif options == "red": 
            console.print(f"[italic red] {msg} [/italic red]", justify="left")
        elif options == "green": 
            console.print(f"[italic green] {msg} [/italic green]", justify="left")

        return 
