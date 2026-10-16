pool = await asyncpg.create_pool(
    os.environ["DATABASE_URL"],
    ssl="require",
    min_size=1,
    max_size=4
)
