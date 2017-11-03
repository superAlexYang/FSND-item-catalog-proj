from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_initialize import Category, CategoryItem, User, Base

engine = create_engine('sqlite:///catalog.db')
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

userDemo = User(name="Super Car seller", email="carsSelling@udacity.com",
             picture='http://www.car-brand-names.com/wp-content/uploads/2015/04/American-car-brands-logos-720x477.png')
session.add(userDemo)
session.commit()

category1 = Category(name="Ford", user_id=1)

session.add(category1)
session.commit()

item1 = CategoryItem(name="Mustang", user_id=1, description="The Ford Mustang is an American car manufactured by Ford. It was originally based on the platform of the second generation North American Ford Falcon, a compact car. The original 1962 Ford Mustang I two-seater concept car had evolved into the 1963 Mustang II four-seater concept car which Ford used to pretest how the public would take interest in the first production Mustang. The 1963 Mustang II concept car was designed with a variation of the production model's front and rear ends with a roof that was 2.7 inches shorter. Introduced early on April 17, 1964, the 1965 Mustang was the automaker's most successful launch since the Model A. The Mustang has undergone several transformations to its current sixth generation", category=category1)

session.add(item1)
session.commit()

item2 = CategoryItem(name="Super Duty", user_id=1,  description="The Ford F-Series Super Duty is a series of trucks manufactured by Ford Motor Company. Introduced in 1998 for the 1999 model year, the F-Series Super Duty trucks marked the addition of a heavy-duty pickup to the Ford F-Series range, including the F-250 and F-350 pickups; the previous 1987-1997 F-Super Duty chassis cabs were replaced by the F-450 and F-550 Super Duty", category=category1)

session.add(item2)
session.commit()

item3 = CategoryItem(name="Focus", user_id=1, description="The Ford Focus is a compact automobile manufactured by the Ford Motor Company since 1998. Designed under Alex Trotman's Ford 2000 plan, which aimed to globalize model development and sell one compact vehicle worldwide, the Focus was primarily designed by Ford of Europe's German and British teams. The Focus was released in July 1998 in Europe, succeeding the Ford Escort, and replaced the Mazda Familia-derived Ford Laser in Asia and Oceania along with the Laser-based North American Escort. Wayne Stamping & Assembly started producing the Focus for North America with sales beginning in 1999.", category=category1)

session.add(item3)
session.commit()

category2 = Category(name="Tesla", user_id=1)

session.add(category2)
session.commit()

item01 = CategoryItem(name="Model 3", user_id=1, description="The Tesla Model 3 is a mid-size all-electric four-door luxury sedan manufactured and marketed by Tesla, Inc.[1] According to Tesla officials the standard Model 3 delivers an EPA rated all-electric range of 220 miles (350 km) and the long-range model delivers 334 miles (540 km). The Model 3 has a minimalist dashboard with only a center-mounted LCD touchscreen.", category=category2)

session.add(item1)
session.commit()

item2 = CategoryItem(name="Model X", user_id=1,  description="The Tesla Model X is a full-sized, all-electric, luxury, crossover SUV made by Tesla, Inc.", category=category2)

session.add(item2)
session.commit()

item3 = CategoryItem(name="Model S", user_id=1, description="The Tesla Model S is a full-sized all-electric five-door, luxury liftback, produced by Tesla, Inc., and introduced on 22 June 2012. It scored a perfect 5.0 NHTSA automobile safety rating.", category=category2)

session.add(item3)
session.commit()

category3 = Category(name="Benz", user_id=1)

session.add(category3)
session.commit()

item1 = CategoryItem(name="S class", user_id=1, description="The Mercedes-Benz S-Class, formerly known as Sonderklasse, is a series of luxury flagship vehicles produced by the German automaker Mercedes-Benz, a division of German company Daimler AG. The S-Class designation for top-of-the-line Mercedes-Benz models was officially introduced in 1972 with the W116, and has remained in use ever since.", category=category3)

session.add(item1)
session.commit()

item2 = CategoryItem(name="G class", user_id=1, description="The Mercedes-Benz G-Class, sometimes called G-Wagen, is a mid-size four-wheel drive luxury SUV manufactured by Magna Steyr (formerly Steyr-Daimler-Puch) in Austria and sold by Mercedes-Benz. In certain markets, it has been sold under the Puch name as Puch G.", category=category3)

session.add(item2)
session.commit()

category4 = Category(name="Jeep", user_id=1)

session.add(category4)
session.commit()

item1 = CategoryItem(name="Wrangler", user_id=1, description="The Jeep Wrangler is a compact and mid-size four-wheel drive off-road vehicle manufactured by Jeep, currently in its third generation.", category=category3)

session.add(item1)
session.commit()

categories = session.query(Category).all()
for category in categories:
    print "Category: " + category.name