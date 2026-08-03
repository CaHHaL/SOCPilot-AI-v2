"""
SOCPilot AI — Setup RAG Database
==================================
Run this script once before using SOCPilot AI to populate the ChromaDB
knowledge base with the seed cybersecurity corpus.

This data is used by the RAG node to enrich investigations with
MITRE ATT&CK context, malware analysis, and response methodologies.
"""

import logging
from rich.console import Console

from socpilot.config.settings import settings
from socpilot.memory.long_term import get_long_term_memory
from socpilot.rag.seed_documents import SEED_DOCUMENTS

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
console = Console()

def setup():
    console.print("[bold cyan]SOCPilot AI — Knowledge Base Initialisation[/bold cyan]")
    
    if not settings.embedding_model:
        console.print("[bold red]Error: No embedding model configured.[/bold red]")
        return
        
    console.print(f"Using embedding model: [bold]{settings.embedding_model}[/bold]")
    console.print(f"Persistence directory: [bold]{settings.chroma_persist_path}[/bold]")
    
    with console.status("Initialising ChromaDB (may take a moment to download embedding model)..."):
        ltm = get_long_term_memory()
        initial_count = ltm.knowledge_count
        
    console.print(f"Current knowledge base size: [bold]{initial_count}[/bold] documents.")
    
    if initial_count > 0:
        console.print("[yellow]Knowledge base already contains documents. Seeding will update existing or add new ones.[/yellow]")
        
    with console.status(f"Seeding {len(SEED_DOCUMENTS)} documents..."):
        for doc_id, text, metadata in SEED_DOCUMENTS:
            ltm.add_knowledge(text=text, doc_id=doc_id, metadata=metadata)
            
    final_count = ltm.knowledge_count
    console.print(f"[bold green]Success![/bold green] Knowledge base now contains {final_count} documents.")
    console.print("\nYou can now run investigations using [bold]python main.py[/bold]")

if __name__ == "__main__":
    setup()
