from dataclasses import dataclass

@dataclass
class Config:
    concurrency: int = 50
    timeout: int = 10
    user_agent: str = "MyNet/1.0"
    ports: list[int] = None

    def __post_init__(self):
        if self.ports is None:
            self.ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 53, 3306, 5432]
