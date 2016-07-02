from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import create_engine
import os, sys, datetime, json, pickle, logging
from functools import wraps
from models import Setting

db = create_engine('sqlite:///threatnoteapis.db')

DeclarativeBase = declarative_base()
Session = sessionmaker(bind=db)

class DBCache(DeclarativeBase):
    __tablename__ = 'dbcache'
    id = Column(Integer, primary_key=True)
    calling_function = Column(String)
    hashed_args = Column(String)
    args = Column(String)
    kwargs = Column(String)
    retrieved_date = Column(DateTime)
    data = Column(String)

if not os.path.exists('threatnoteapis.db'):
    DeclarativeBase.metadata.create_all(db)

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    if isinstance(obj, datetime.date):
        serial = obj.isoformat()
        return serial

def dbcache(fn, refresh_time=86400, force_update=False):
    '''dbcache memoizes functions by storing their results in a database.
    refresh_time is used to determine how old an entry must be before
    we run a new query. Note: the old query will still be in the DB for
    analytics/historical anaylsis.
    refresh_time = 0:, cached results will ALWAYS be returned, new queries
    will never be run.
    refresh_time >= 0: caches results will be returned if they are refresh_time
    seconds old or newer.
    Default of 2592000 seconds == 30 days'''
    @wraps(fn)
    def wrapper(*args, **kwargs):
        hashed_args = arg_dump(args, kwargs)
        session = Session()
        force_update = False
        if ('dbcache_force_update' in kwargs and
                kwargs['dbcache_force_update'] == True):
            del kwargs['dbcache_force_update']
            force_update = True
        cached_entry = session.query(DBCache).filter_by(
                           calling_function=fn.__name__,
                           hashed_args=hashed_args).order_by(DBCache.id.desc()).first()
        settings = Setting.query.filter_by(_id=1).first()
        refresh_time = settings.cache_ttl
        if refresh_time == '':
            refresh_time = 86400
        if cached_entry: # Check age and force_update if too old
            now = datetime.datetime.now()
            retrieved = cached_entry.retrieved_date
            age = now - retrieved
            if age.seconds >= refresh_time:
                force_update = True
        if cached_entry and not force_update:
            logging.debug('Found cached entry in DB')
            return json.loads(cached_entry.data)
        else:
            logging.debug('Not in DB, looking up...')
            data = fn(*args, **kwargs)
            try:
                new_entry = DBCache(calling_function=fn.__name__,
                                    hashed_args=hashed_args,
                                    args=str(args),
                                    kwargs=str(kwargs),
                                    retrieved_date=datetime.datetime.now(),
                                    data=json.dumps(data, default=json_serial))
                session.add(new_entry)
                session.commit()
            except:
                logging.debug('Could not store in DB, continuing')
            return data
    return wrapper


def arg_dump(*args, **kwargs):
    return pickle.dumps((args,kwargs))

#class _HashedSeq(list):
#    __slots__ = 'hashvalue'
#
#    def __init__(self, tup, hash=hash):
#        self[:] = tup
#        self.hashvalue = hash(tup)
#
#    def __hash__(self):
#        return self.hashvalue
#
#def _make_key(args, kwds,
#             kwd_mark = (object(),),
#             fasttypes = {int, str, frozenset, type(None)},
#             sorted=sorted, tuple=tuple, type=type, len=len):
#    'Make a cache key from optionally typed positional and keyword arguments'
#    key = args
#    if kwds:
#        sorted_items = sorted(kwds.items())
#        key += kwd_mark
#        for item in sorted_items:
#            key += item
#    elif len(key) == 1 and type(key[0]) in fasttypes:
#        return key[0]
#    return _HashedSeq(key)


