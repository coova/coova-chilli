/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * lookup()
 * Generates a 32 bit hash.
 * Based on public domain code by Bob Jenkins
 * It should be one of the best hash functions around in terms of both
 * statistical properties and speed. It is NOT recommended for cryptographic
 * purposes.
 **/

#ifndef _LOOKUP_H
#define _LOOKUP_H

uint32_t lookup(uint8_t *k, size_t length, uint32_t level);

#endif	/* !_LOOKUP_H */
